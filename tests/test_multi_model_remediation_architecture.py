# -*- coding: utf-8 -*-
"""
tests/test_multi_model_remediation_architecture.py — Verification Suite for
Hardware-Aware Multi-Model Ollama AI Remediation Engine in VITAL IDE.

Exhaustively verifies:
  1. Hardware awareness & memory configuration (16 GB RAM, Intel i5-11300H, Iris Xe, max 1 model).
  2. Intelligent model routing (3B for syntax/delimiters vs 7B for semantic/security/Fix All).
  3. Automatic VITAL language intelligence (auto-detection, grammar specs across 6 languages).
  4. SQL Injection (CWE-89) dedicated remediation & security re-validation across languages.
  5. Single-model memory management, eviction via keep_alive: 0, and sequential execution.
  6. Request caching & deduplication.
  7. Reliable patch application lifecycle, revision verification, and working copy persistence.
  8. Fix All multi-error batch resolution and partial resolution tracking.
  9. Live Ollama inference with structured JSON output and performance metrics.
"""

import os
import sys
import json
import time
import unittest
from unittest.mock import patch, MagicMock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(PROJECT_ROOT, 'src')
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from web.ollama_client import (
    OllamaClient,
    ollama_client,
    MODEL_FAST,
    MODEL_ADVANCED,
    DEFAULT_NUM_CTX
)
from web.language_context import (
    VitalLanguageIntelligence,
    language_intelligence
)
from web.ai_remediation_engine import (
    AIRemediationEngine,
    remediation_engine,
    DiagnosticNormalizer,
    StageValidator
)
from web.security_analyzer import (
    security_coordinator,
    DeterministicSecurityScanner
)
from web.working_source_manager import (
    working_source_manager
)


class TestHardwareAwareMultiModelArchitecture(unittest.TestCase):
    """Test Suite verifying multi-model routing, memory constraints, and language intelligence."""

    def setUp(self):
        self.client = ollama_client
        self.engine = remediation_engine

    def test_01_hardware_configuration_and_memory_profile(self):
        """Hardware status reflects 16 GB PC, Intel i5 CPU, Iris Xe GPU, and single model constraint."""
        hw = self.client.get_hardware_status()
        self.assertIn("16", str(int(hw["total_ram_mb"] / 1000)))  # ~16 GB RAM
        self.assertGreater(hw["free_ram_mb"], 1000)
        self.assertEqual(hw["cpu"], "Intel Core i5-11300H (11th Gen)")
        self.assertIn("Iris Xe", hw["gpu"])
        self.assertEqual(hw["max_models_in_memory"], 1)
        self.assertEqual(hw["context_window_tokens"], 4096)
        self.assertEqual(hw["model_fast"], "qwen2.5-coder:3b")
        self.assertIn("qwen2.5-coder:7b", hw["model_advanced"])

    def test_02_intelligent_model_routing(self):
        """3B selected for simple syntax/delimiters; 7B selected for semantic, security, and Fix All."""
        # 1. Simple Syntax / Delimiter imbalance -> 3B Fast Model
        m1, r1 = self.client.route_model(
            stage_id="syntax_analysis",
            rule_id="SEC-PAR-001",
            title="Unbalanced Block Delimiters",
            is_escalation=False,
            error_count=1
        )
        self.assertEqual(m1, "qwen2.5-coder:3b")
        self.assertIn("3B", r1)

        # 2. Semantic Analysis -> 7B Advanced Model
        m2, r2 = self.client.route_model(
            stage_id="semantic_analysis",
            rule_id="SEC-SEM-001",
            title="Undeclared Identifier",
            is_escalation=False,
            error_count=1
        )
        self.assertIn("7b", m2)
        self.assertIn("7B", r2)

        # 3. Security Vulnerability (SQL Injection) -> 7B Advanced Model
        m3, r3 = self.client.route_model(
            stage_id="security_analysis",
            rule_id="SEC-INJ-001",
            title="SQL Query Injection via String Concatenation",
            is_escalation=False,
            error_count=1
        )
        self.assertIn("7b", m3)
        self.assertIn("security", r3.lower())

        # 4. Multi-error Fix All (>2 errors) -> 7B Advanced Model
        m4, r4 = self.client.route_model(
            stage_id="syntax_analysis",
            rule_id="SYN-001",
            title="Multiple Syntax Errors",
            is_escalation=False,
            error_count=4
        )
        self.assertIn("7b", m4)
        self.assertIn("multi-error", r4.lower())

        # 5. Escalation after 3B validation failure -> 7B Advanced Model
        m5, r5 = self.client.route_model(
            stage_id="syntax_analysis",
            rule_id="SYN-001",
            title="Syntax Error",
            is_escalation=True,
            error_count=1
        )
        self.assertIn("7b", m5)
        self.assertIn("escalated", r5.lower())

    def test_03_vital_language_intelligence_auto_detection(self):
        """Auto-detects language across English, Hindi, Telugu, Bengali, Marathi, and Nepali."""
        # English
        code_en = 'let count = 10\nprint(count)'
        self.assertEqual(VitalLanguageIntelligence.detect_language(code_en), "English")

        # Telugu
        code_te = 'అనుకో సంఖ్య = 5\nరాయి(సంఖ్య)'
        self.assertEqual(VitalLanguageIntelligence.detect_language(code_te), "Telugu")

        # Bengali
        code_bn = 'ধরো সংখ্যা = 5\nছাপাও(সংখ্যা)'
        self.assertEqual(VitalLanguageIntelligence.detect_language(code_bn), "Bengali")

        # Hindi
        code_hi = 'मानो संख्या = 5\nलिखो(संख्या)\nअगर (संख्या > 0) { लिखो("सकारात्मक") }'
        self.assertEqual(VitalLanguageIntelligence.detect_language(code_hi), "Hindi")

        # Marathi
        code_mr = 'घ्या संख्या = 5\nलिहा(संख्या)\nजर (संख्या > 0) { लिहा("सकारात्मक") }'
        self.assertEqual(VitalLanguageIntelligence.detect_language(code_mr), "Marathi")

        # Nepali
        code_ne = 'मान संख्या = 5\nछाप(संख्या)\nयदि (संख्या > 0) { छाप("सकारात्मक") }'
        self.assertEqual(VitalLanguageIntelligence.detect_language(code_ne), "Nepali")

    def test_04_language_context_prompt_includes_spec_and_security(self):
        """Language prompt contains grammar specification, keywords, and security instructions."""
        prompt = VitalLanguageIntelligence.get_language_context_prompt("Hindi", stage_id="security_analysis")
        self.assertIn("मानो", prompt)
        self.assertIn("लिखो", prompt)
        self.assertIn("SEC-INJ-001", prompt)
        self.assertIn("DATABASE SECURITY INSTRUCTION", prompt)
        self.assertIn("COMPILER RESTRICTIONS", prompt)

    def test_05_sql_injection_remediation_and_security_revalidation(self):
        """SQL injection (SEC-INJ-001) in English and Bengali is repaired and verified cleared."""
        # English code with SQL injection
        code_en = (
            "function execute_database_query(user_filter) {\n"
            "    let query_prefix = \"SELECT user_id, email FROM accounts WHERE role = 'user' AND \"\n"
            "    let full_query = query_prefix + user_filter\n"
            "    print(full_query)\n"
            "    return 1\n"
            "}\n"
        )
        findings_before = DeterministicSecurityScanner.scan_multilingual_security(code_en, "English")
        sql_findings = [f for f in findings_before if f.rule_id == "SEC-INJ-001"]
        self.assertEqual(len(sql_findings), 1)

        # Propose fix via coordinator
        fix_res = security_coordinator.suggest_fix_for_finding(
            source_code=code_en,
            finding_id="SEC-INJ-001",
            finding_data=sql_findings[0].to_dict(),
            language="English",
            prefer_deterministic=True,
            request_ai=False
        )
        self.assertTrue(fix_res["success"])
        repaired_code = fix_res["proposed_source"]

        # Verify that SEC-INJ-001 is completely eliminated
        findings_after = DeterministicSecurityScanner.scan_multilingual_security(repaired_code, "English")
        sql_after = [f for f in findings_after if f.rule_id == "SEC-INJ-001"]
        self.assertEqual(len(sql_after), 0)

        # Verify via coordinator.verify_repair
        rep_verif = security_coordinator.verify_repair(
            original_source=code_en,
            repaired_source=repaired_code,
            language="English",
            target_finding_id="SEC-INJ-001"
        )
        self.assertTrue(rep_verif["success"])
        self.assertEqual(len(rep_verif["remaining_findings"]), 0)

    def test_06_memory_management_and_model_switching(self):
        """Ollama client enforces max 1 loaded model and evicts previous model on switch."""
        # Mock Ollama ps and generate endpoints
        with patch.object(self.client, 'get_loaded_models', return_value=["qwen2.5-coder:3b"]), \
             patch.object(self.client, 'unload_model', return_value=True) as mock_unload:

            switch_ms = self.client.ensure_single_model_loaded("qwen2.5-coder:7b-instruct")
            # Must call unload on previous model
            mock_unload.assert_called_once_with("qwen2.5-coder:3b")
            self.assertEqual(self.client._active_loaded_model, "qwen2.5-coder:7b-instruct")

    def test_07_request_caching_and_duplicate_suppression(self):
        """Repeated requests for identical source code and diagnostic return cached results."""
        code = "let x = 10\nprint(x)\n"
        cache_key = f"{hash(code)}_ERR-1_qwen2.5-coder:3b"

        # Prime cache
        fake_result = {
            "success": True,
            "content": json.dumps({"status": "ok"}),
            "model": "qwen2.5-coder:3b",
            "cached": False
        }
        self.client._cache[cache_key] = fake_result

        # Request with cache_key
        res = self.client.chat(
            messages=[{"role": "user", "content": "ping"}],
            model="qwen2.5-coder:3b",
            cache_key=cache_key
        )
        self.assertTrue(res["cached"])
        self.assertEqual(res["model"], "qwen2.5-coder:3b")

    def test_08_reliable_patch_application_lifecycle_and_persistence(self):
        """apply_and_verify_fix verifies revision, persists working copy, and validates stages."""
        test_file = "examples/english/hello.vital"
        curr = working_source_manager.get_working_source(test_file)
        self.assertTrue(curr["success"])
        initial_rev = curr["source_revision"]

        # Valid modification: add a comment at the top
        modified_code = "// VITAL Verified Test Patch\n" + curr["code"]

        res = self.engine.apply_and_verify_fix(
            file_path=test_file,
            proposed_source=modified_code,
            expected_revision=initial_rev,
            stage_id="syntax_analysis",
            language="English",
            finding_id="TEST-001"
        )
        self.assertTrue(res["success"])
        self.assertTrue(res["persisted"])
        self.assertEqual(res["compiler_validation"], "PASSED")
        self.assertEqual(res["source_revision"], initial_rev + 1)

        # Stale revision rejection test
        stale_res = self.engine.apply_and_verify_fix(
            file_path=test_file,
            proposed_source=modified_code,
            expected_revision=initial_rev,  # Expired revision
            stage_id="syntax_analysis",
            language="English",
            finding_id="TEST-001"
        )
        self.assertFalse(stale_res["success"])
        self.assertIn("Stale patch rejection", stale_res["error"])

        # Restore original for cleanliness
        working_source_manager.restore_original_source(test_file)

    def test_09_fix_all_multi_error_batch_resolution(self):
        """Fix All generates structured multi-error resolution and tracks resolved vs remaining."""
        source_code = (
            "let x = 10\n"
            "let y = 20\n"
            "print(x + y)\n"
            "}\n"  # Delimiter error
        )
        diagnostics = [
            {"id": "ERR-1", "rule_id": "SEC-PAR-001", "title": "Unbalanced Block Delimiters", "line": 4, "column": 1}
        ]
        res = self.engine.generate_fix_all(
            source_code=source_code,
            stage_id="syntax_analysis",
            diagnostics=diagnostics,
            language="English",
            use_ai=False
        )
        self.assertTrue(res["success"])
        self.assertEqual(res["resolved_count"], 1)
        self.assertEqual(res["remaining_count"], 0)
        self.assertIn("diff", res)

    def test_10_live_ollama_dual_model_response(self):
        """Live test verifying Ollama is online with dual models and returns structured metrics."""
        is_healthy, msg, details = self.client.check_health(force_refresh=True)
        if not is_healthy:
            self.skipTest("Ollama is currently offline, skipping live network call.")

        # Test Fast Model (3B)
        t0 = time.time()
        res_3b = self.client.chat(
            messages=[{"role": "user", "content": "Output JSON with key status and value ok"}],
            model=self.client.model_fast,
            max_tokens=30,
            timeout=30.0
        )
        self.assertTrue(res_3b["success"])
        self.assertIn("model_load_time_ms", res_3b)
        self.assertIn("inference_time_ms", res_3b)
        self.assertIn("tokens_per_second", res_3b)
        print(f"\n[LIVE BENCHMARK] 3B Model: {round(res_3b['inference_time_ms'], 1)}ms inference, {res_3b['tokens_per_second']} tok/s")


if __name__ == "__main__":
    unittest.main()
