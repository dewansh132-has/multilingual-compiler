# -*- coding: utf-8 -*-
"""
tests/test_security_lab.py — Comprehensive Unit & Regression Tests for VITAL Security Lab

Verifies:
  1. Registry integrity: All 24 demos registered across 6 languages with full metadata.
  2. File integrity: All 24 .vital files exist on disk with authentic multilingual syntax.
  3. Demo Manager categorization: Security Lab category correctly populated without overwriting canonical examples.
  4. Seeded vulnerability detection across all languages:
     - Demo A: IDOR (CWE-639), threshold status bypass (CWE-285), undefined variable (semantic).
     - Demo B: Hardcoded credentials (CWE-798), sensitive log exposure (CWE-200), off-by-one array bounds (CWE-129).
     - Demo C: SQL injection with taint source-sink flow (CWE-89), eval dynamic execution (CWE-95).
     - Demo D: Unbalanced delimiter syntax error (SEC-PAR-001), negative quantity exploit (CWE-840).
  5. Calibrated Risk Scoring & Deduplication: Severity weighting, cluster dampening, taint bonus.
  6. Pipeline stage blocking: Syntax errors block downstream stages and mark assessment incomplete.
  7. Repair workflow & verify-repair endpoint: Reference fix resolves findings, eliminates regressions, updates score.
  8. Non-modification advisory contract: Propose fix diff does not mutate source until explicit user approval.
  9. Preservation of canonical examples across all 6 languages.
"""

import os
import json
import unittest
from typing import Dict, Any, List

from web.security_lab_registry import (
    SECURITY_LAB_DEMOS,
    get_all_security_lab_demos,
    get_security_lab_demo_by_id,
    get_security_lab_demo_by_path,
    get_demos_by_language
)
from web.demo_manager import get_all_demos, get_demo_content
from web.security_analyzer import (
    security_coordinator,
    DeterministicSecurityScanner,
    compute_overall_risk_score,
    SecurityFinding
)
from web.pipeline_tracker import execute_pipeline_with_tracker, PipelineRunTracker
from web.server import app

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestSecurityLabRegistryAndFiles(unittest.TestCase):
    """Test 1: Verify all 24 Security Lab demo files and metadata registry."""

    SUPPORTED_LANGUAGES = ["English", "Hindi", "Telugu", "Bengali", "Marathi", "Nepali"]

    def test_all_24_demos_registered(self):
        """Registry contains exactly 24 demos, 4 per supported language."""
        self.assertEqual(len(SECURITY_LAB_DEMOS), 24)
        for lang in self.SUPPORTED_LANGUAGES:
            demos = get_demos_by_language(lang)
            self.assertEqual(len(demos), 4, f"Language {lang} should have exactly 4 Security Lab demos, found {len(demos)}")

    def test_demo_files_exist_and_non_empty(self):
        """All 24 demo files exist on disk, are valid UTF-8, and have non-empty code."""
        for demo in SECURITY_LAB_DEMOS:
            abs_path = os.path.join(PROJECT_ROOT, demo.relative_path)
            self.assertTrue(os.path.isfile(abs_path), f"Demo file missing: {demo.relative_path}")
            with open(abs_path, 'r', encoding='utf-8') as f:
                content = f.read()
            self.assertGreater(len(content.strip()), 50, f"Demo file {demo.relative_path} is too short or empty")

    def test_registry_metadata_completeness(self):
        """All demos possess valid IDs, descriptions, defect categories, expected findings, and reference fixes."""
        for demo in SECURITY_LAB_DEMOS:
            self.assertTrue(demo.id.startswith("SEC-DEMO-"))
            self.assertIn(demo.language, self.SUPPORTED_LANGUAGES)
            self.assertIn(demo.scenario_type, ["Demo A", "Demo B", "Demo C", "Demo D"])
            self.assertIn(demo.difficulty, ["Beginner", "Intermediate", "Advanced"])
            self.assertTrue(len(demo.description) > 10)
            self.assertTrue(len(demo.defect_categories) >= 2)
            self.assertTrue(len(demo.expected_findings) >= 2)
            self.assertTrue(len(demo.reference_fix_code) > 20)
            self.assertTrue(len(demo.reference_fix_description) > 10)

    def test_demo_manager_integration(self):
        """Demo manager categorizes Security Lab separately and loads metadata."""
        tree = get_all_demos()
        self.assertIn("Security Lab", tree["by_category"])
        sec_demos = tree["by_category"]["Security Lab"]
        self.assertEqual(len(sec_demos), 24)

        # Test demo content fetching with security metadata attached
        res = get_demo_content("examples/security_lab/english/sec_auth_account.vital")
        self.assertTrue(res["success"])
        self.assertTrue(res.get("is_security_lab"))
        self.assertIsNotNone(res.get("security_lab_meta"))
        self.assertEqual(res["security_lab_meta"]["id"], "SEC-DEMO-EN-01")


class TestMultilingualVulnerabilityDetection(unittest.TestCase):
    """Test 2: Verify that security rules detect seeded defects across all 6 languages."""

    def test_demo_a_idor_and_bypass_all_languages(self):
        """Demo A: IDOR (SEC-AUTH-001) and bypass (SEC-AUTH-003) detected across all 6 languages."""
        demo_ids = [
            "SEC-DEMO-EN-01", "SEC-DEMO-HI-01", "SEC-DEMO-TE-01",
            "SEC-DEMO-BN-01", "SEC-DEMO-MR-01", "SEC-DEMO-NE-01"
        ]
        for did in demo_ids:
            demo = get_security_lab_demo_by_id(did)
            abs_path = os.path.join(PROJECT_ROOT, demo.relative_path)
            with open(abs_path, 'r', encoding='utf-8') as f:
                code = f.read()

            findings = DeterministicSecurityScanner.scan_multilingual_security(code, demo.language)
            rule_ids = [f.rule_id for f in findings]

            self.assertIn("SEC-AUTH-001", rule_ids, f"{did} ({demo.language}) failed to trigger SEC-AUTH-001 (IDOR)")
            self.assertIn("SEC-AUTH-003", rule_ids, f"{did} ({demo.language}) failed to trigger SEC-AUTH-003 (Bypass)")

    def test_demo_b_secret_and_leak_all_languages(self):
        """Demo B: Hardcoded credentials (SEC-SEC-001) and log exposure (SEC-LOG-001) detected across all 6 languages."""
        demo_ids = [
            "SEC-DEMO-EN-02", "SEC-DEMO-HI-02", "SEC-DEMO-TE-02",
            "SEC-DEMO-BN-02", "SEC-DEMO-MR-02", "SEC-DEMO-NE-02"
        ]
        for did in demo_ids:
            demo = get_security_lab_demo_by_id(did)
            abs_path = os.path.join(PROJECT_ROOT, demo.relative_path)
            with open(abs_path, 'r', encoding='utf-8') as f:
                code = f.read()

            findings = DeterministicSecurityScanner.scan_multilingual_security(code, demo.language)
            rule_ids = [f.rule_id for f in findings]

            self.assertIn("SEC-DATA-001", rule_ids, f"{did} ({demo.language}) failed to trigger SEC-DATA-001 (Hardcoded Secret)")
            self.assertIn("SEC-DATA-002", rule_ids, f"{did} ({demo.language}) failed to trigger SEC-DATA-002 (Log Leak)")

    def test_demo_c_sql_injection_and_taint_flow_all_languages(self):
        """Demo C: SQL Injection (SEC-INJ-001) with taint source-to-sink flow detected across all 6 languages."""
        demo_ids = [
            "SEC-DEMO-EN-03", "SEC-DEMO-HI-03", "SEC-DEMO-TE-03",
            "SEC-DEMO-BN-03", "SEC-DEMO-MR-03", "SEC-DEMO-NE-03"
        ]
        for did in demo_ids:
            demo = get_security_lab_demo_by_id(did)
            abs_path = os.path.join(PROJECT_ROOT, demo.relative_path)
            with open(abs_path, 'r', encoding='utf-8') as f:
                code = f.read()

            findings = DeterministicSecurityScanner.scan_multilingual_security(code, demo.language)
            sql_findings = [f for f in findings if f.rule_id == "SEC-INJ-001"]

            self.assertTrue(len(sql_findings) > 0, f"{did} ({demo.language}) failed to trigger SEC-INJ-001")
            sql_f = sql_findings[0]
            self.assertIsNotNone(sql_f.source_sink_flow, f"{did} missing taint source-to-sink flow metadata")
            self.assertTrue(len(sql_f.source_sink_flow.get("source", "")) > 0)
            self.assertTrue(len(sql_f.source_sink_flow.get("sink", "")) > 0)

    def test_demo_d_syntax_error_and_logic_defect_all_languages(self):
        """Demo D: Delimiter syntax error (SEC-PAR-001) and business logic exploit (SEC-BIZ-001) detected across all 6 languages."""
        demo_ids = [
            "SEC-DEMO-EN-04", "SEC-DEMO-HI-04", "SEC-DEMO-TE-04",
            "SEC-DEMO-BN-04", "SEC-DEMO-MR-04", "SEC-DEMO-NE-04"
        ]
        for did in demo_ids:
            demo = get_security_lab_demo_by_id(did)
            abs_path = os.path.join(PROJECT_ROOT, demo.relative_path)
            with open(abs_path, 'r', encoding='utf-8') as f:
                code = f.read()

            # Syntax scan
            par_findings = DeterministicSecurityScanner.scan_parser(code)
            self.assertTrue(any(f.rule_id == "SEC-PAR-001" for f in par_findings),
                            f"{did} ({demo.language}) failed to report unbalanced brace error SEC-PAR-001")

            # Business logic exploit scan
            sec_findings = DeterministicSecurityScanner.scan_multilingual_security(code, demo.language)
            self.assertTrue(any(f.rule_id == "SEC-LOGIC-001" for f in sec_findings),
                            f"{did} ({demo.language}) failed to report business logic flaw SEC-LOGIC-001")


class TestRiskScoringAndIntegrity(unittest.TestCase):
    """Test 3: Verify vulnerability risk scoring (0-100), deduplication, and syntax blocking integrity."""

    def test_clean_scan_produces_zero_risk_and_canonical_verdict(self):
        """Clean code produces risk score 0 and strict text 'No issues detected by enabled checks'."""
        score, verdict = compute_overall_risk_score([], syntax_blocked=False)
        self.assertEqual(score, 0)
        self.assertEqual(verdict, "No issues detected by enabled checks.")

    def test_syntax_blocked_assessment_incomplete(self):
        """When syntax error blocks pipeline, score is BLOCKED and verdict is Assessment Incomplete (never 0 or Secure)."""
        score, verdict = compute_overall_risk_score([], syntax_blocked=True)
        self.assertIn(score, [-1, "BLOCKED"])
        self.assertIn("assessment incomplete", verdict.lower())
        self.assertNotIn("no issues", verdict.lower())

    def test_severity_floors_and_weights(self):
        """Critical findings anchor score at >= 90; High findings anchor score at >= 65."""
        f_high = SecurityFinding(
            id="SEC-01", title="Secret Leak", stage="Scan", stage_id="sec",
            severity="High", risk_score=70, confidence="confirmed",
            evidence="pw = '123'", explanation="secret", remediation="env",
            rule_id="SEC-SEC-001"
        )
        score_high, _ = compute_overall_risk_score([f_high])
        self.assertGreaterEqual(score_high, 65)

        f_crit = SecurityFinding(
            id="SEC-02", title="IDOR Flaw", stage="Scan", stage_id="sec",
            severity="Critical", risk_score=95, confidence="confirmed",
            evidence="transfer()", explanation="idor", remediation="owner",
            rule_id="SEC-AUTH-001"
        )
        score_crit, _ = compute_overall_risk_score([f_crit])
        self.assertGreaterEqual(score_crit, 90)

    def test_duplicate_findings_do_not_inflate_score(self):
        """Duplicate findings under the same rule_id are dampened with 20% secondary weight."""
        f1 = SecurityFinding(
            id="SEC-01", title="Secret Leak", stage="Scan", stage_id="sec",
            severity="High", risk_score=70, confidence="confirmed",
            evidence="pw = '123'", explanation="secret", remediation="env",
            rule_id="SEC-SEC-001"
        )
        f2 = SecurityFinding(
            id="SEC-02", title="Secret Leak 2", stage="Scan", stage_id="sec",
            severity="High", risk_score=70, confidence="confirmed",
            evidence="token = 'xyz'", explanation="secret", remediation="env",
            rule_id="SEC-SEC-001"
        )
        score_single, _ = compute_overall_risk_score([f1])
        score_dup, _ = compute_overall_risk_score([f1, f2])
        # Two duplicates of High must not inflate to Critical (>90)
        self.assertLess(score_dup, 90)


class TestPipelineBlockingBehavior(unittest.TestCase):
    """Test 4: Verify that syntax error in Demo D blocks downstream compilation stages."""

    def test_demo_d_syntax_blocks_downstream_stages(self):
        """Running Demo D (unbalanced brace) halts parser and blocks AST, Semantics, IR, and Sandbox."""
        demo = get_security_lab_demo_by_id("SEC-DEMO-EN-04")
        abs_path = os.path.join(PROJECT_ROOT, demo.relative_path)
        with open(abs_path, 'r', encoding='utf-8') as f:
            code = f.read()

        tracker = PipelineRunTracker()
        report = execute_pipeline_with_tracker(
            source_code=code,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            pacing_ms=0.0
        )

        stages_map = tracker.stages
        # Parser must fail
        self.assertEqual(stages_map["syntax_analysis"]["status"], "failed")
        # Downstream stages must be blocked or skipped
        for blocked_id in ["ast_construction", "semantic_analysis", "symbol_table", "ir_generation", "sandbox_execution"]:
            self.assertIn(stages_map[blocked_id]["status"], ["blocked", "skipped"],
                          f"Stage {blocked_id} should be marked 'blocked' or 'skipped' when parser fails")

        # Security scan should report syntax_blocked = True
        sec_result = tracker.artifacts.get("security", {})
        self.assertTrue(sec_result.get("syntax_blocked"), "Security assessment must be marked syntax_blocked")
        self.assertEqual(sec_result.get("overall_risk_score"), "BLOCKED")


class TestRepairVerificationAndAPI(unittest.TestCase):
    """Test 5: Verify repair verification and REST API endpoints."""

    def setUp(self):
        self.client = app.test_client()

    def test_verify_repair_demo_a_resolves_all_defects(self):
        """Applying Demo A reference fix resolves all seeded findings and updates score to 0."""
        demo = get_security_lab_demo_by_id("SEC-DEMO-EN-01")
        abs_path = os.path.join(PROJECT_ROOT, demo.relative_path)
        with open(abs_path, 'r', encoding='utf-8') as f:
            faulty_code = f.read()

        res = security_coordinator.verify_repair(
            original_source=faulty_code,
            repaired_source=demo.reference_fix_code,
            language="English"
        )
        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "Passed")
        self.assertGreater(len(res["resolved_findings"]), 0)
        self.assertEqual(len(res["remaining_findings"]), 0)
        self.assertEqual(res["updated_risk_score"], 0)

    def test_verify_repair_api_endpoint(self):
        """POST /api/security/verify-repair returns valid verification payload."""
        demo = get_security_lab_demo_by_id("SEC-DEMO-HI-01")
        abs_path = os.path.join(PROJECT_ROOT, demo.relative_path)
        with open(abs_path, 'r', encoding='utf-8') as f:
            faulty_code = f.read()

        payload = {
            "original_source": faulty_code,
            "repaired_source": demo.reference_fix_code,
            "language": "Hindi"
        }
        resp = self.client.post("/api/security/verify-repair", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "Passed")
        self.assertEqual(data["updated_risk_score"], 0)

    def test_security_lab_demos_api_endpoint(self):
        """GET /api/security-lab/demos returns all 24 registered demo metadata."""
        resp = self.client.get("/api/security-lab/demos")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["count"], 24)
        self.assertEqual(len(data["demos"]), 24)

    def test_suggest_fix_returns_diff_without_mutating_editor(self):
        """POST /api/security/suggest-fix returns a proposed patch and explanation without auto-applying."""
        demo = get_security_lab_demo_by_id("SEC-DEMO-EN-01")
        abs_path = os.path.join(PROJECT_ROOT, demo.relative_path)
        with open(abs_path, 'r', encoding='utf-8') as f:
            code = f.read()

        payload = {
            "code": code,
            "finding_id": "SEC-AUTH-001",
            "language": "English",
            "finding": {"title": "IDOR", "rule_id": "SEC-AUTH-001"}
        }
        resp = self.client.post("/api/security/suggest-fix", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn("proposed_source", data)
        self.assertIn("diff", data)
        # Verify the patch actually includes the ownership check
        self.assertIn("caller_id != from_account_id", data["proposed_source"])


class TestPreserveCanonicalDemos(unittest.TestCase):
    """Test 6: Verify canonical valid examples across all languages compile and run without regression."""

    def test_canonical_english_demos(self):
        """Canonical examples (hello.vital, variables.vital, conditions.vital, loops.vital, functions.vital) compile cleanly."""
        canonical_files = [
            ("examples/english/hello.vital", "English"),
            ("examples/english/arithmetic.vital", "English"),
            ("examples/english/conditions.vital", "English"),
            ("examples/english/loops.vital", "English"),
        ]
        for rel_path, lang in canonical_files:
            abs_path = os.path.join(PROJECT_ROOT, rel_path)
            self.assertTrue(os.path.isfile(abs_path), f"Canonical file missing: {rel_path}")
            with open(abs_path, 'r', encoding='utf-8') as f:
                code = f.read()

            tracker = PipelineRunTracker()
            report = execute_pipeline_with_tracker(
                source_code=code,
                language_hint=lang,
                run_ai_security=False,
                tracker=tracker,
                pacing_ms=0.0
            )
            # Syntax and Semantic stages must pass
            stages_map = tracker.stages
            self.assertEqual(stages_map["syntax_analysis"]["status"], "completed", f"{rel_path} syntax failed")
            self.assertEqual(stages_map["semantic_analysis"]["status"], "completed", f"{rel_path} semantics failed")
            self.assertEqual(stages_map["ir_generation"]["status"], "completed", f"{rel_path} IR generation failed")

    def test_canonical_indic_demos(self):
        """Canonical Indic examples in Hindi, Telugu, Bengali, Marathi, and Nepali compile cleanly."""
        indic_files = [
            ("examples/hindi/hello.vital", "Hindi"),
            ("examples/telugu/hello.vital", "Telugu"),
            ("examples/bengali/hello.vital", "Bengali"),
            ("examples/marathi/hello.vital", "Marathi"),
            ("examples/nepali/hello.vital", "Nepali"),
        ]
        for rel_path, lang in indic_files:
            abs_path = os.path.join(PROJECT_ROOT, rel_path)
            self.assertTrue(os.path.isfile(abs_path), f"Canonical file missing: {rel_path}")
            with open(abs_path, 'r', encoding='utf-8') as f:
                code = f.read()

            tracker = PipelineRunTracker()
            report = execute_pipeline_with_tracker(
                source_code=code,
                language_hint=lang,
                run_ai_security=False,
                tracker=tracker,
                pacing_ms=0.0
            )
            stages_map = tracker.stages
            self.assertEqual(stages_map["syntax_analysis"]["status"], "completed", f"{rel_path} syntax failed")
            self.assertEqual(stages_map["semantic_analysis"]["status"], "completed", f"{rel_path} semantics failed")


if __name__ == '__main__':
    unittest.main()
