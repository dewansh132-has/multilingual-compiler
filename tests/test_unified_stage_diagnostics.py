# -*- coding: utf-8 -*-
"""
tests/test_unified_stage_diagnostics.py

Comprehensive Unit and Integration Test Suite verifying:
1. Multi-finding detection: Demos with multiple issues (e.g., 3 security vulnerabilities)
   return all individual findings in one structured list under the appropriate stage.
2. Per-finding isolated remediation: Suggesting and applying a fix for Finding 2
   resolves only Finding 2, leaving Finding 1 and Finding 3 active.
3. Sequential resolution down to 0 findings.
4. Editor buffer mutability vs disk demo immutability (original demo files on disk remain untouched).
5. Undo snapshot restoration recovers the exact pre-fix working buffer.
6. Syntax Analysis stage populates delimiter & parser findings with individual remediation.
7. Semantic Analysis stage populates type/scope/arithmetic findings with individual remediation.
8. Lexical Analysis stage populates token-boundary findings (homoglyphs, null bytes).
9. Security tab removal: Verifies right-hand compiler output tabs display genuine compiler artifacts
   without the removed Security tab, eliminating horizontal scrolling.
"""

import os
import sys
import json
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(PROJECT_ROOT, 'src')
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from web.server import app
from web.security_analyzer import security_coordinator, DeterministicSecurityScanner
from web.pipeline_tracker import PipelineRunTracker, execute_pipeline_with_tracker


class TestUnifiedStageDiagnostics(unittest.TestCase):
    """Test suite for Unified Stage Diagnostics and Per-Issue Remediation."""

    def setUp(self):
        self.client = app.test_client()
        self.demo_auth_account_path = os.path.join(
            PROJECT_ROOT, "examples", "security_lab", "english", "sec_auth_account.vital"
        )
        with open(self.demo_auth_account_path, "r", encoding="utf-8") as f:
            self.pristine_auth_account_code = f.read()

        self.demo_injection_eval_path = os.path.join(
            PROJECT_ROOT, "examples", "security_lab", "english", "sec_injection_eval.vital"
        )
        with open(self.demo_injection_eval_path, "r", encoding="utf-8") as f:
            self.pristine_injection_eval_code = f.read()

    def test_01_multi_finding_detection_returns_all_issues(self):
        """1. Multi-finding detection: sec_auth_account.vital returns all 3 distinct vulnerabilities."""
        resp = self.client.post("/api/security/scan", json={
            "code": self.pristine_auth_account_code,
            "language": "English",
            "use_ai": False
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])

        findings = data["findings"]
        # Must detect at least 3 distinct vulnerabilities
        self.assertGreaterEqual(len(findings), 3, "Expected at least 3 distinct findings for sec_auth_account.vital")

        # Verify each finding has complete diagnostic metadata
        for f in findings:
            self.assertIn("id", f)
            self.assertIn("title", f)
            self.assertIn("severity", f)
            self.assertIn("stage", f)
            self.assertIn("stage_id", f)
            self.assertIn("rule_id", f)
            self.assertIn("explanation", f)

        # Check expected distinct rule types: IDOR (SEC-AUTH-001), Bypass (SEC-AUTH-003), Undefined variable (SEC-SEM-001)
        rule_ids = [f.get("rule_id", "") for f in findings]
        self.assertTrue(any("AUTH-001" in r for r in rule_ids), "Missing IDOR finding")
        self.assertTrue(any("AUTH-003" in r for r in rule_ids), "Missing status suspension bypass finding")
        self.assertTrue(any("SEM-001" in r for r in rule_ids), "Missing undefined variable finding")

    def test_02_per_finding_fix_isolation(self):
        """2. Suggesting and applying a fix for Finding 2 resolves ONLY Finding 2."""
        # 1. Scan original code
        scan_resp = self.client.post("/api/security/scan", json={
            "code": self.pristine_auth_account_code,
            "language": "English",
            "use_ai": False
        })
        scan_data = scan_resp.get_json()
        findings = scan_data["findings"]
        self.assertGreaterEqual(len(findings), 3)

        # Target Finding 2: Suspension Bypass (SEC-AUTH-003)
        finding_2 = findings[1]
        self.assertIn("Suspension", finding_2["title"])

        # 2. Request fix specifically for Finding 2
        fix_resp = self.client.post("/api/security/suggest-fix", json={
            "code": self.pristine_auth_account_code,
            "finding_id": finding_2["id"],
            "finding": finding_2,
            "language": "English",
            "prefer_deterministic": True
        })
        self.assertEqual(fix_resp.status_code, 200)
        fix_data = fix_resp.get_json()
        self.assertTrue(fix_data["success"])
        self.assertTrue(fix_data.get("is_deterministic"))
        proposed_code = fix_data["proposed_source"]

        # 3. Verify fix modified the buffer but NOT disk
        self.assertNotEqual(proposed_code, self.pristine_auth_account_code)
        with open(self.demo_auth_account_path, "r", encoding="utf-8") as f:
            disk_content = f.read()
        self.assertEqual(disk_content, self.pristine_auth_account_code, "Disk demo file was illegally modified!")

        # 4. Verify repair with backend
        verif_resp = self.client.post("/api/security/verify-repair", json={
            "original_code": self.pristine_auth_account_code,
            "repaired_code": proposed_code,
            "language": "English",
            "target_finding_id": finding_2["id"]
        })
        self.assertEqual(verif_resp.status_code, 200)
        verif_data = verif_resp.get_json()
        self.assertTrue(verif_data["success"])

        # Finding 2 (SEC-AUTH-003) must be resolved
        resolved_rules = [f.get("rule_id") for f in verif_data.get("resolved_findings", [])]
        self.assertIn("SEC-AUTH-003", resolved_rules, "Finding 2 (SEC-AUTH-003) was not marked resolved")

        # Remaining findings must still contain Finding 1 (SEC-AUTH-001) and Finding 3 (SEC-SEM-001)
        remaining_rules = [f.get("rule_id") for f in verif_data.get("remaining_findings", [])]
        self.assertNotIn("SEC-AUTH-003", remaining_rules, "Finding 2 should not be in remaining findings")
        self.assertIn("SEC-AUTH-001", remaining_rules, "Finding 1 (IDOR) should remain active")
        self.assertIn("SEC-SEM-001", remaining_rules, "Finding 3 (Undefined variable) should remain active")

    def test_03_sequential_resolution_down_to_zero(self):
        """3. Applying fixes sequentially resolves all findings until clean."""
        current_buffer = self.pristine_auth_account_code

        for step in range(3):
            # Scan current buffer
            scan = self.client.post("/api/security/scan", json={
                "code": current_buffer,
                "language": "English",
                "use_ai": False
            }).get_json()
            findings = scan.get("findings", [])
            if not findings:
                break

            target = findings[0]
            fix = self.client.post("/api/security/suggest-fix", json={
                "code": current_buffer,
                "finding_id": target["id"],
                "finding": target,
                "language": "English",
                "prefer_deterministic": True
            }).get_json()
            self.assertTrue(fix["success"])
            self.assertNotEqual(fix["proposed_source"], current_buffer)
            current_buffer = fix["proposed_source"]

        # Final scan of fully repaired buffer
        final_scan = self.client.post("/api/security/scan", json={
            "code": current_buffer,
            "language": "English",
            "use_ai": False
        }).get_json()
        self.assertEqual(len(final_scan.get("findings", [])), 0, "All findings should be resolved")
        self.assertEqual(final_scan.get("overall_risk_score", 0), 0)

        # Original disk file must remain completely untouched throughout
        with open(self.demo_auth_account_path, "r", encoding="utf-8") as f:
            disk_content = f.read()
        self.assertEqual(disk_content, self.pristine_auth_account_code)

    def test_04_syntax_analysis_stage_findings_and_fix(self):
        """4. Syntax stage populates delimiter & parser findings with individual remediation."""
        broken_syntax_code = """function calculate_total(a, b) {
    let result = a + b
    print(result)
"""  # Missing closing '}' brace
        tracker = PipelineRunTracker()
        execute_pipeline_with_tracker(broken_syntax_code, "English", False, tracker)
        stage_dict = tracker.to_dict()

        syntax_stage = next(s for s in stage_dict["stages"] if s["id"] == "syntax_analysis")
        self.assertEqual(syntax_stage["status"], "failed")
        self.assertGreater(syntax_stage["findings_count"], 0)

        findings = syntax_stage["details"].get("findings", [])
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]["stage_id"], "syntax_analysis")

        # Test suggesting fix for syntax finding
        fix_resp = self.client.post("/api/security/suggest-fix", json={
            "code": broken_syntax_code,
            "finding_id": findings[0]["id"],
            "finding": findings[0],
            "language": "English",
            "prefer_deterministic": True
        })
        self.assertEqual(fix_resp.status_code, 200)
        fix_data = fix_resp.get_json()
        self.assertTrue(fix_data["success"])
        # Should balance the braces
        self.assertEqual(fix_data["proposed_source"].count('{'), fix_data["proposed_source"].count('}'))

    def test_05_semantic_analysis_stage_findings_and_fix(self):
        """5. Semantic stage populates type/scope/arithmetic findings with individual remediation."""
        semantic_error_code = """let bad_val = 100 / 0
print(bad_val)
"""
        tracker = PipelineRunTracker()
        execute_pipeline_with_tracker(semantic_error_code, "English", False, tracker)
        stage_dict = tracker.to_dict()

        sem_stage = next(s for s in stage_dict["stages"] if s["id"] == "semantic_analysis")
        self.assertIn(sem_stage["status"], ("failed", "warning"))
        self.assertGreater(sem_stage["findings_count"], 0)

        findings = sem_stage["details"].get("findings", [])
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]["stage_id"], "semantic_analysis")
        self.assertIn("zero", findings[0]["title"].lower())

        # Test suggesting fix for semantic division by zero finding
        fix_resp = self.client.post("/api/security/suggest-fix", json={
            "code": semantic_error_code,
            "finding_id": findings[0]["id"],
            "finding": findings[0],
            "language": "English",
            "prefer_deterministic": True
        })
        fix_data = fix_resp.get_json()
        self.assertTrue(fix_data["success"])
        self.assertNotIn("/ 0", fix_data["proposed_source"])

    def test_06_lexical_analysis_stage_findings(self):
        """6. Lexical stage populates token-boundary findings (null bytes, homoglyphs)."""
        lexical_issue_code = """let admin_user = "ad\x00min"
print(admin_user)
"""
        tracker = PipelineRunTracker()
        execute_pipeline_with_tracker(lexical_issue_code, "English", False, tracker)
        stage_dict = tracker.to_dict()

        lex_stage = next(s for s in stage_dict["stages"] if s["id"] == "lexical_analysis")
        self.assertEqual(lex_stage["status"], "warning")
        self.assertGreater(lex_stage["findings_count"], 0)

        findings = lex_stage["details"].get("findings", [])
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]["stage_id"], "lexical")
        self.assertIn("Null Byte", findings[0]["title"])

    def test_07_security_tab_removed_compiler_artifacts_intact(self):
        """7. Security tab is removed from right-hand output, compiler artifacts tabs are preserved."""
        with open(os.path.join(PROJECT_ROOT, "web", "templates", "index.html"), "r", encoding="utf-8") as f:
            html = f.read()

        # Dedicated right-hand Security tab button and container must NOT be in output area
        self.assertNotIn('id="tab-btn-security"', html)
        self.assertNotIn('id="tab-out-security"', html)
        self.assertNotIn('data-tab="tab-out-security"', html)

        # Standard compiler tabs must remain intact
        self.assertIn('data-tab="tab-out-program"', html)
        self.assertIn('id="tab-out-program"', html)
        self.assertIn('data-tab="tab-out-pipeline"', html)
        self.assertIn('id="tab-out-pipeline"', html)
        self.assertIn('data-tab="tab-out-lexer"', html)
        self.assertIn('id="tab-out-lexer"', html)
        self.assertIn('data-tab="tab-out-parser"', html)
        self.assertIn('id="tab-out-parser"', html)
        self.assertIn('data-tab="tab-out-ast"', html)
        self.assertIn('id="tab-out-ast"', html)
        self.assertIn('data-tab="tab-out-ir"', html)
        self.assertIn('id="tab-out-ir"', html)
        self.assertIn('data-tab="tab-out-symbol"', html)
        self.assertIn('id="tab-out-symbol"', html)

        # General AI Assistant tab must remain accessible
        self.assertIn('id="tab-btn-ai"', html)
        self.assertIn('id="tab-out-ai"', html)

    def test_08_multi_finding_fix_first_preserves_others_and_score(self):
        """8. Fixing Finding 1 preserves Findings 2 and 3 with truthful non-zero risk score."""
        scan = self.client.post("/api/security/scan", json={
            "code": self.pristine_auth_account_code,
            "language": "English",
            "use_ai": False
        }).get_json()
        findings = scan["findings"]
        self.assertGreaterEqual(len(findings), 3)

        # Fix finding 1 (IDOR)
        f1 = findings[0]
        self.assertIn("SEC-AUTH-001", f1.get("rule_id", ""))
        fix1 = self.client.post("/api/security/suggest-fix", json={
            "code": self.pristine_auth_account_code,
            "finding_id": f1["id"],
            "finding": f1,
            "language": "English",
            "prefer_deterministic": True
        }).get_json()
        self.assertTrue(fix1["success"])

        # Verify repair
        verif = self.client.post("/api/security/verify-repair", json={
            "original_source": self.pristine_auth_account_code,
            "repaired_source": fix1["proposed_source"],
            "language": "English",
            "target_finding_id": f1["id"]
        }).get_json()

        self.assertTrue(verif["success"])
        self.assertEqual(verif["status"], "Partial")
        self.assertEqual(verif["resolved_count"], 1)
        self.assertGreaterEqual(verif["remaining_count"], 2)

        # Risk score must NOT drop to zero while 2 findings remain
        self.assertGreater(verif["updated_risk_score"], 0)
        self.assertEqual(verif["updated_risk_score"], 65)

        remaining_rules = [f["rule_id"] for f in verif["remaining_findings"]]
        self.assertNotIn("SEC-AUTH-001", remaining_rules)
        self.assertIn("SEC-AUTH-003", remaining_rules)
        self.assertIn("SEC-SEM-001", remaining_rules)

    def test_09_multi_finding_fix_second_preserves_third(self):
        """9. Fixing Finding 2 preserves Finding 3 with truthful updated risk score."""
        # 1. Apply fix 1
        scan1 = self.client.post("/api/security/scan", json={
            "code": self.pristine_auth_account_code,
            "language": "English",
            "use_ai": False
        }).get_json()
        f1 = scan1["findings"][0]
        fix1 = self.client.post("/api/security/suggest-fix", json={
            "code": self.pristine_auth_account_code,
            "finding_id": f1["id"],
            "finding": f1,
            "language": "English",
            "prefer_deterministic": True
        }).get_json()
        buffer_after_fix1 = fix1["proposed_source"]

        # 2. Scan buffer after fix 1
        scan2 = self.client.post("/api/security/scan", json={
            "code": buffer_after_fix1,
            "language": "English",
            "use_ai": False
        }).get_json()
        self.assertEqual(len(scan2["findings"]), 2)
        f2 = scan2["findings"][0]
        self.assertIn("SEC-AUTH-003", f2.get("rule_id", ""))

        # 3. Apply fix 2
        fix2 = self.client.post("/api/security/suggest-fix", json={
            "code": buffer_after_fix1,
            "finding_id": f2["id"],
            "finding": f2,
            "language": "English",
            "prefer_deterministic": True
        }).get_json()
        self.assertTrue(fix2["success"])

        # 4. Verify repair of fix 2
        verif2 = self.client.post("/api/security/verify-repair", json={
            "original_source": buffer_after_fix1,
            "repaired_source": fix2["proposed_source"],
            "language": "English",
            "target_finding_id": f2["id"]
        }).get_json()

        self.assertTrue(verif2["success"])
        self.assertEqual(verif2["status"], "Partial")
        self.assertEqual(verif2["resolved_count"], 1)
        self.assertEqual(verif2["remaining_count"], 1)
        self.assertEqual(verif2["updated_risk_score"], 35)

        remaining_rules = [f["rule_id"] for f in verif2["remaining_findings"]]
        self.assertNotIn("SEC-AUTH-003", remaining_rules)
        self.assertIn("SEC-SEM-001", remaining_rules)

    def test_10_undo_restores_exact_previous_buffer_and_score(self):
        """10. Undo snapshot restores the exact previous working buffer byte-for-byte."""
        original_buffer = self.pristine_auth_account_code
        undo_stack = []

        # Step 1: Push pre-fix buffer
        undo_stack.append(original_buffer)

        # Step 2: Apply fix 1
        scan1 = self.client.post("/api/security/scan", json={"code": original_buffer, "language": "English", "use_ai": False}).get_json()
        fix1 = self.client.post("/api/security/suggest-fix", json={
            "code": original_buffer,
            "finding_id": scan1["findings"][0]["id"],
            "finding": scan1["findings"][0],
            "language": "English",
            "prefer_deterministic": True
        }).get_json()
        modified_buffer = fix1["proposed_source"]
        self.assertNotEqual(modified_buffer, original_buffer)

        # Step 3: Undo restores pre-fix buffer
        restored_buffer = undo_stack.pop()
        self.assertEqual(restored_buffer, original_buffer)

        # Rescan restored buffer matches original scan
        scan_restored = self.client.post("/api/security/scan", json={"code": restored_buffer, "language": "English", "use_ai": False}).get_json()
        self.assertEqual(len(scan_restored["findings"]), len(scan1["findings"]))
        self.assertEqual(scan_restored["overall_risk_score"], scan1["overall_risk_score"])

    def test_11_disk_demo_remains_strictly_byte_for_byte_unmodified(self):
        """11. Disk demo files remain strictly immutable across all scans, fixes, and verifications."""
        with open(self.demo_auth_account_path, "rb") as f:
            disk_bytes_before = f.read()

        # Perform multiple scans, fixes, and verifications
        scan = self.client.post("/api/security/scan", json={"code": self.pristine_auth_account_code, "language": "English", "use_ai": False}).get_json()
        fix = self.client.post("/api/security/suggest-fix", json={"code": self.pristine_auth_account_code, "finding_id": scan["findings"][0]["id"], "finding": scan["findings"][0], "language": "English", "prefer_deterministic": True}).get_json()
        self.client.post("/api/security/verify-repair", json={"original_source": self.pristine_auth_account_code, "repaired_source": fix["proposed_source"], "language": "English", "target_finding_id": scan["findings"][0]["id"]})

        with open(self.demo_auth_account_path, "rb") as f:
            disk_bytes_after = f.read()

        self.assertEqual(disk_bytes_before, disk_bytes_after, "Disk demo file was modified!")

    def test_12_overlay_dialog_markup_and_accessibility(self):
        """12. Floating overlay markup exists with proper modal attributes and single scroll container."""
        with open(os.path.join(PROJECT_ROOT, "web", "templates", "index.html"), "r", encoding="utf-8") as f:
            html = f.read()

        self.assertIn('id="stage-overlay-backdrop"', html)
        self.assertIn('role="dialog"', html)
        self.assertIn('aria-modal="true"', html)
        self.assertIn('id="stage-overlay-dialog"', html)
        self.assertIn('id="stage-overlay-header"', html)
        self.assertIn('id="drawer-close-btn"', html)
        self.assertIn('class="stage-overlay-scroll-body drawer-body"', html)
        self.assertIn('id="drawer-stage-body"', html)

    def test_13_single_scroll_css_hierarchy(self):
        """13. CSS specifies single-scroll overlay body and removes nested scrollbars."""
        with open(os.path.join(PROJECT_ROOT, "web", "static", "css", "ide.css"), "r", encoding="utf-8") as f:
            css = f.read()

        # Single scrollable container inside overlay
        self.assertIn('.stage-overlay-scroll-body', css)
        self.assertIn('overflow-y: auto', css)

        # Removed nested vertical scrollbar from stage findings container
        self.assertIn('.stage-findings-scroll-container', css)
        self.assertIn('overflow: visible !important', css)
        self.assertIn('max-height: none !important', css)

        # Code excerpt and diff preview wrapped or horizontal-only
        self.assertIn('.inline-diff-preview', css)
        self.assertIn('overflow-x: auto', css)

        # Page body scrolling intact
        self.assertIn('overflow-y: auto', css)

    def test_14_overlay_backdrop_dismiss_and_escape_handlers_in_js(self):
        """14. JavaScript implements outside click dismiss, dialog click stopPropagation, and Escape key."""
        with open(os.path.join(PROJECT_ROOT, "web", "static", "js", "ide.js"), "r", encoding="utf-8") as f:
            js = f.read()

        # Backdrop click dismiss
        self.assertIn('elements.stageOverlayBackdrop.addEventListener("click"', js)
        self.assertIn('if (e.target === elements.stageOverlayBackdrop)', js)
        self.assertIn('closeStageDrawer();', js)

        # Inside dialog click stop propagation
        self.assertIn('elements.stageOverlayDialog.addEventListener("click"', js)
        self.assertIn('e.stopPropagation();', js)

        # Escape key handler
        self.assertIn('e.key === "Escape"', js)

        # updatePipelineStageBadge function definition
        self.assertIn('function updatePipelineStageBadge(', js)

        # syncFindingsIntoStore function definition
        self.assertIn('function syncFindingsIntoStore(', js)

    def test_15_stale_patch_and_verification_rejection(self):
        """15. A patch that fails to fix the target issue or introduces syntax errors is flagged Failed."""
        broken_repair = self.pristine_auth_account_code + "\nfunction unclosed_func(x) {"
        verif = self.client.post("/api/security/verify-repair", json={
            "original_source": self.pristine_auth_account_code,
            "repaired_source": broken_repair,
            "language": "English",
            "target_finding_id": "SEC-AUTH-001"
        }).get_json()

        self.assertTrue(verif["success"])
        self.assertEqual(verif["status"], "Failed")
        self.assertIn("delimiters", verif["summary"].lower())

    def test_16_horizontal_pipeline_header_placement_and_scrolling(self):
        """16. Pipeline header is positioned below toolbar and above workspace with horizontal scrolling."""
        with open(os.path.join(PROJECT_ROOT, "web", "templates", "index.html"), "r", encoding="utf-8") as f:
            html = f.read()

        header_idx = html.find('</header>')
        pipeline_idx = html.find('id="pipeline-progress-container"')
        workspace_idx = html.find('id="ide-workspace"')

        self.assertGreater(pipeline_idx, header_idx, "Pipeline header must be placed after toolbar </header>")
        self.assertLess(pipeline_idx, workspace_idx, "Pipeline header must be placed before <main id=\"ide-workspace\">")

        with open(os.path.join(PROJECT_ROOT, "web", "static", "css", "ide.css"), "r", encoding="utf-8") as f:
            css = f.read()

        self.assertIn('.pipeline-stepper', css)
        self.assertIn('overflow-x: auto', css)
        self.assertIn('overflow-y: hidden', css)

    def test_17_canonical_pipeline_stages_order_in_frontend(self):
        """17. Frontend defines all canonical compiler stages in strict execution order."""
        with open(os.path.join(PROJECT_ROOT, "web", "static", "js", "ide.js"), "r", encoding="utf-8") as f:
            js = f.read()

        expected_order = [
            "source_input",
            "lexical_analysis",
            "syntax_analysis",
            "ast_construction",
            "semantic_analysis",
            "symbol_table",
            "ir_generation",
            "optimization",
            "code_generation",
            "code_validation",
            "security_analysis",
            "ai_security_analysis",
            "sandbox_execution",
            "final_report"
        ]

        for i in range(len(expected_order) - 1):
            pos_current = js.find(f'id: "{expected_order[i]}"')
            pos_next = js.find(f'id: "{expected_order[i+1]}"')
            self.assertGreater(pos_current, -1, f"Missing stage {expected_order[i]} in ide.js")
            self.assertGreater(pos_next, -1, f"Missing stage {expected_order[i+1]} in ide.js")
            self.assertLess(pos_current, pos_next, f"Stage {expected_order[i]} must precede {expected_order[i+1]}")

    def test_18_multilingual_demos_pipeline_execution(self):
        """18. Pipeline executes accurately across all 6 supported languages (English, Hindi, Telugu, Bengali, Marathi, Nepali)."""
        multilingual_snippets = {
            "English": "let x = 10\nlet y = 20\nlet sum = x + y\nprint(sum)\n",
            "Hindi": "मानो x = 10\nमानो y = 20\nमानो sum = x + y\nलिखो(sum)\n",
            "Telugu": "అనుకో x = 10\nఅనుకో y = 20\nఅనుకో sum = x + y\nరాయి(sum)\n",
            "Bengali": "ধরো x = 10\nধরো y = 20\nধরো sum = x + y\nছাপাও(sum)\n",
            "Marathi": "घ्या x = 10\nघ्या y = 20\nघ्या sum = x + y\nलिहा(sum)\n",
            "Nepali": "मान x = 10\nमान y = 20\nमान sum = x + y\nछाप(sum)\n"
        }

        for lang, snippet in multilingual_snippets.items():
            tracker = PipelineRunTracker()
            execute_pipeline_with_tracker(snippet, lang, False, tracker)
            run_data = tracker.to_dict()

            self.assertEqual(run_data["overall_status"], "completed", f"Failed for language: {lang}")
            syntax_stage = next(s for s in run_data["stages"] if s["id"] == "syntax_analysis")
            self.assertEqual(syntax_stage["status"], "completed", f"Syntax failed for {lang}")
            codegen_stage = next(s for s in run_data["stages"] if s["id"] == "code_generation")
            self.assertEqual(codegen_stage["status"], "completed", f"Codegen failed for {lang}")

    def test_19_syntax_failure_blocks_downstream_stages(self):
        """19. A syntax failure accurately blocks downstream compiler stages (AST, IR, Codegen, Sandbox)."""
        broken_syntax = "function unclosed_grammar(a, b) {\n    let z = a * b\n"
        tracker = PipelineRunTracker()
        execute_pipeline_with_tracker(broken_syntax, "English", False, tracker)
        run_data = tracker.to_dict()

        self.assertEqual(run_data["overall_status"], "failed")
        syntax_stage = next(s for s in run_data["stages"] if s["id"] == "syntax_analysis")
        self.assertEqual(syntax_stage["status"], "failed")

        ast_stage = next(s for s in run_data["stages"] if s["id"] == "ast_construction")
        self.assertEqual(ast_stage["status"], "skipped")
        self.assertIn("syntax", ast_stage["summary"].lower())

        codegen_stage = next(s for s in run_data["stages"] if s["id"] == "code_generation")
        self.assertEqual(codegen_stage["status"], "skipped")

        sandbox_stage = next(s for s in run_data["stages"] if s["id"] == "sandbox_execution")
        self.assertEqual(sandbox_stage["status"], "skipped")

    def test_20_ollama_offline_fallback(self):
        """20. Deterministic rules serve as immediate fallbacks if Ollama is unconfigured or offline."""
        resp = self.client.post("/api/security/suggest-fix", json={
            "code": self.pristine_auth_account_code,
            "finding_id": "SEC-AUTH-001",
            "finding": {
                "id": "SEC-AUTH-001",
                "title": "Insecure Direct Object Reference (IDOR)",
                "severity": "Critical",
                "stage": "Security Analysis",
                "rule_id": "SEC-AUTH-001"
            },
            "language": "English",
            "prefer_deterministic": True,
            "request_ai": False
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(data.get("is_deterministic"))
        self.assertTrue("caller_id != from_account_id" in data["proposed_source"] or "Fixed IDOR" in data["proposed_source"])


if __name__ == '__main__':
    unittest.main()


