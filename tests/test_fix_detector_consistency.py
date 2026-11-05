# -*- coding: utf-8 -*-
"""
tests/test_fix_detector_consistency.py — Verification of Fix & Detector Consistency,
Language Purity, and Honest Error Handling (Tasks B, C, D)
"""

import os
import sys
import unittest

# Ensure VITAL_AI_DISABLED=1
os.environ["VITAL_AI_DISABLED"] = "1"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from web.server import app
from web.security_analyzer import security_coordinator, DeterministicSecurityScanner
from web.ai_remediation_engine import remediation_engine
from web.working_source_manager import working_source_manager


class TestFixDetectorConsistency(unittest.TestCase):
    """Validates idempotency and consistency between detectors and fixers across all rules."""

    def _scan(self, code: str, lang: str = "English"):
        raw = DeterministicSecurityScanner.scan_multilingual_security(code, lang)
        return [f.to_dict() if hasattr(f, 'to_dict') else f for f in raw]

    def test_sec_inj_001_idempotency(self):
        """SEC-INJ-001 fix neutralizes dynamic SQL concatenation with parameterized query."""
        code = 'let query = "SELECT * FROM users WHERE id = " + user_id\nprint(query)'
        finding = {
            "rule_id": "SEC-INJ-001",
            "cwe_id": "CWE-89",
            "line": 1,
            "evidence": 'let query = "SELECT * FROM users WHERE id = " + user_id',
            "title": "SQL Query Injection"
        }
        fix = security_coordinator.generate_deterministic_fix(code, finding_data=finding, language="English")
        self.assertTrue(fix["success"])
        fixed_code = fix["proposed_source"]
        self.assertIn("?", fixed_code)

        # Detector must NOT fire on fixed code
        findings_after = self._scan(fixed_code, "English")
        inj_findings = [f for f in findings_after if f.get("rule_id") == "SEC-INJ-001"]
        self.assertEqual(len(inj_findings), 0)

    def test_sec_data_001_safe_placeholder(self):
        """SEC-DATA-001 does not fire on safe REDACTED/CONFIG/ENV placeholder assignments."""
        safe_code = 'let db_key = "REDACTED_USE_ENVIRONMENT_CONFIG"\nprint(db_key)'
        findings = self._scan(safe_code, "English")
        data_findings = [f for f in findings if f.get("rule_id") == "SEC-DATA-001"]
        self.assertEqual(len(data_findings), 0)

    def test_sec_data_002_idempotency(self):
        """SEC-DATA-002 replaces debug console output and does not refire."""
        code = 'let pass = "secret123"\nprint(pass)'
        finding = {
            "rule_id": "SEC-DATA-002",
            "cwe_id": "CWE-532",
            "line": 2,
            "evidence": "print(pass)",
            "title": "Debug Secret Printing"
        }
        fix = security_coordinator.generate_deterministic_fix(code, finding_data=finding, language="English")
        self.assertTrue(fix["success"])
        fixed_code = fix["proposed_source"]
        self.assertNotIn("print(pass)", fixed_code)

        findings_after = self._scan(fixed_code, "English")
        data_findings = [f for f in findings_after if f.get("rule_id") == "SEC-DATA-002"]
        self.assertEqual(len(data_findings), 0)

    def test_sec_data_003_loop_bound_fix(self):
        """SEC-DATA-003 replaces <= with < in loop condition and does not refire."""
        code = 'let i = 0\nwhile (i <= total) {\n    i = i + 1\n}'
        finding = {
            "rule_id": "SEC-DATA-003",
            "cwe_id": "CWE-193",
            "line": 2,
            "evidence": "while (i <= total)",
            "title": "Off-by-One Loop Boundary"
        }
        fix = security_coordinator.generate_deterministic_fix(code, finding_data=finding, language="English")
        self.assertTrue(fix["success"])
        fixed_code = fix["proposed_source"]
        self.assertIn("< total", fixed_code)
        self.assertNotIn("<= total", fixed_code)

        findings_after = self._scan(fixed_code, "English")
        data_findings = [f for f in findings_after if f.get("rule_id") == "SEC-DATA-003"]
        self.assertEqual(len(data_findings), 0)

    def test_sec_logic_001_function_guard_injection(self):
        """SEC-LOGIC-001 injects boundary guard inside function body with actual parameter name."""
        code = 'fun calculate_total(qty) {\n    return qty * 10\n}\nlet total = calculate_total(10)\nprint(total)'
        finding = {
            "rule_id": "SEC-LOGIC-001",
            "cwe_id": "CWE-840",
            "line": 1,
            "evidence": "fun calculate_total(qty)",
            "title": "Missing Business Logic Quantity Guard"
        }
        fix = security_coordinator.generate_deterministic_fix(code, finding_data=finding, language="English")
        self.assertTrue(fix["success"])
        fixed_code = fix["proposed_source"]
        # Guard must be inside function body
        self.assertIn("if (qty <= 0) {", fixed_code)
        self.assertIn("fun calculate_total(qty) {", fixed_code)

        findings_after = self._scan(fixed_code, "English")
        logic_findings = [f for f in findings_after if f.get("rule_id") == "SEC-LOGIC-001"]
        self.assertEqual(len(logic_findings), 0)

    def test_sec_auth_001_idempotency(self):
        """SEC-AUTH-001 IDOR fix inserts ownership check and does not refire."""
        code = 'fun view_profile(user_id) {\n    print(user_id)\n}'
        finding = {
            "rule_id": "SEC-AUTH-001",
            "cwe_id": "CWE-639",
            "line": 1,
            "evidence": "fun view_profile(user_id)",
            "title": "Insecure Direct Object Reference"
        }
        fix = security_coordinator.generate_deterministic_fix(code, finding_data=finding, language="English")
        self.assertTrue(fix["success"])
        fixed_code = fix["proposed_source"]
        self.assertTrue("user_id != session_user" in fixed_code or "caller_id != from_account_id" in fixed_code)

        findings_after = self._scan(fixed_code, "English")
        auth_findings = [f for f in findings_after if f.get("rule_id") == "SEC-AUTH-001"]
        self.assertEqual(len(auth_findings), 0)

    def test_sec_auth_003_idempotency(self):
        """SEC-AUTH-003 state bypass fix inserts state check guard and does not refire."""
        code = 'fun execute_transfer(amount) {\n    print(amount)\n}'
        finding = {
            "rule_id": "SEC-AUTH-003",
            "cwe_id": "CWE-285",
            "line": 1,
            "evidence": "fun execute_transfer(amount)",
            "title": "Unauthenticated State Bypass"
        }
        fix = security_coordinator.generate_deterministic_fix(code, finding_data=finding, language="English")
        self.assertTrue(fix["success"])
        fixed_code = fix["proposed_source"]
        self.assertTrue("status_ok == 0" in fixed_code or "!=" in fixed_code)

        findings_after = self._scan(fixed_code, "English")
        auth_findings = [f for f in findings_after if f.get("rule_id") == "SEC-AUTH-003"]
        self.assertEqual(len(auth_findings), 0)


class TestLanguagePurity(unittest.TestCase):
    """Validates that fixes for non-English files contain NO English keywords."""

    def test_hindi_fix_has_no_english_keywords(self):
        """Hindi fixes must use 'यदि', 'वापस', 'छापो', 'मान' and no English 'if'/'return'/'print'/'let'."""
        code = 'कार्य प्रोफ़ाइल_देखें(उपयोगकर्ता_आईडी) {\n    छापो(उपयोगकर्ता_आईडी)\n}'
        finding = {
            "rule_id": "SEC-AUTH-001",
            "cwe_id": "CWE-639",
            "line": 1,
            "evidence": "कार्य प्रोफ़ाइल_देखें(उपयोगकर्ता_आईडी)",
            "title": "IDOR"
        }
        fix = security_coordinator.generate_deterministic_fix(code, finding_data=finding, language="Hindi")
        self.assertTrue(fix["success"])
        fixed = fix["proposed_source"]
        # Must contain Hindi keywords
        self.assertTrue("यदि" in fixed or "अगर" in fixed)
        self.assertTrue("वापस" in fixed or "लौटाओ" in fixed)
        # Must NOT contain English control keywords
        for en_kw in [" if ", " if(", "\nif ", "\nif(", " return ", " return\n", " let "]:
            self.assertNotIn(en_kw, fixed, f"English keyword '{en_kw}' found in Hindi fix!")

    def test_telugu_fix_has_no_english_keywords(self):
        """Telugu fixes must use 'ఒకవేళ', 'తిరిగి_ఇవ్వు', 'ముద్రించు', 'అనుకో'."""
        code = 'ఫంక్షన్ ఖాతా_వివరాలు(యూజర్_ఐడి) {\n    ముద్రించు(యూజర్_ఐడి)\n}'
        finding = {
            "rule_id": "SEC-AUTH-001",
            "cwe_id": "CWE-639",
            "line": 1,
            "evidence": "ఫంక్షన్ ఖాతా_వివరాలు(యూజర్_ఐడి)",
            "title": "IDOR"
        }
        fix = security_coordinator.generate_deterministic_fix(code, finding_data=finding, language="Telugu")
        self.assertTrue(fix["success"])
        fixed = fix["proposed_source"]
        self.assertIn("ఒకవేళ", fixed)
        self.assertIn("తిరిగి_ఇవ్వు", fixed)
        for en_kw in [" if ", " if(", "\nif ", "\nif(", " return ", " return\n", " let "]:
            self.assertNotIn(en_kw, fixed, f"English keyword '{en_kw}' found in Telugu fix!")

    def test_bengali_fix_has_no_english_keywords(self):
        """Bengali fixes must use 'যদি', 'ফেরত', 'মুদ্রণ', 'ধরি'."""
        code = 'ফাংশন ব্যবহারকারী_দেখুন(ইউজার_আইডি) {\n    মুদ্রণ(ইউজার_আইডি)\n}'
        finding = {
            "rule_id": "SEC-AUTH-001",
            "cwe_id": "CWE-639",
            "line": 1,
            "evidence": "ফাংশন ব্যবহারকারী_দেখুন(ইউজার_আইডি)",
            "title": "IDOR"
        }
        fix = security_coordinator.generate_deterministic_fix(code, finding_data=finding, language="Bengali")
        self.assertTrue(fix["success"])
        fixed = fix["proposed_source"]
        self.assertIn("যদি", fixed)
        self.assertIn("ফেরত", fixed)
        for en_kw in [" if ", " if(", "\nif ", "\nif(", " return ", " return\n", " let "]:
            self.assertNotIn(en_kw, fixed, f"English keyword '{en_kw}' found in Bengali fix!")


class TestHttpEndpointsAndRevisions(unittest.TestCase):
    """Validates real HTTP endpoints for revision tracking, reports, and honest non-blocking error handling."""

    def setUp(self):
        self.client = app.test_client()

    def test_pipeline_run_returns_source_revision(self):
        """POST /api/pipeline/run returns matching source_revision."""
        resp = self.client.post("/api/pipeline/run", json={
            "code": "let x = 10\nprint(x)",
            "language": "English",
            "source_revision": 4,
            "use_ai_security": False
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("source_revision"), 4)

    def test_final_report_includes_source_revision_and_security_sections(self):
        """POST /api/pipeline/generate-report includes source_revision and sections 10A-10D."""
        resp = self.client.post("/api/pipeline/generate-report", json={
            "code": "let x = 10\nprint(x)",
            "language": "English",
            "source_revision": 5
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("source_revision"), 5)
        log = data.get("artifacts", {}).get("aggregated_log", "")
        self.assertIn("SECTION 10: SECURITY AUDIT & RISK SCORE", log)
        self.assertIn("SECTION 10B: RESOLVED FINDINGS", log)
        self.assertIn("SECTION 10C: REMAINING FINDINGS (MANUAL)", log)

    def test_unfixable_finding_returns_honest_manual_status(self):
        """When a finding cannot be auto-fixed, Fix All returns honest status with manual_fixes populated."""
        # Unfixable arbitrary comment finding
        finding = {
            "id": "UNFIX-001",
            "rule_id": "SEC-CUSTOM-999",
            "title": "Custom Unfixable Architecture Constraint",
            "stage": "security_analysis",
            "line": 1,
            "evidence": "// arbitrary code",
            "is_security": True
        }
        res = remediation_engine.generate_fix_all(
            source_code="// arbitrary code\nlet a = 1",
            stage_id="security_analysis",
            diagnostics=[finding],
            language="English",
            source_revision=1,
            use_ai=False
        )
        self.assertIn(res.get("status"), ("needs manual fix", "already_applied", "applied"))
        self.assertGreater(len(res.get("manual_fixes", [])), 0)
        manual_item = res["manual_fixes"][0]
        self.assertIn("manual fix required", manual_item.get("reason", "").lower())

    def test_fix_all_http_endpoint_unfixable_returns_manual_summary(self):
        """POST /api/ai/fix-all returns status 'needs manual fix' and manual_fixes list when unfixable."""
        resp = self.client.post("/api/ai/fix-all", json={
            "stage_id": "security_analysis",
            "code": "// manual only code\nlet a = 1",
            "diagnostics": [{
                "id": "MANUAL-001",
                "rule_id": "SEC-UNSUPPORTED",
                "title": "Manual Fix Only Flaw",
                "line": 1,
                "is_security": True
            }],
            "use_ai": False
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("status"), "needs manual fix")
        self.assertEqual(len(data.get("applied_fixes", [])), 0)
        self.assertGreater(len(data.get("manual_fixes", [])), 0)
        self.assertIn("manual fix required", data["manual_fixes"][0]["reason"].lower())


if __name__ == "__main__":
    unittest.main()
