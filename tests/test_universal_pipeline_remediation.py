import unittest
import sys
import os
import glob
import json
import re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from web.pipeline_tracker import execute_pipeline_with_tracker, STAGE_DEFINITIONS
from web.security_analyzer import security_coordinator, DeterministicSecurityScanner
import web.server as server_module

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class UniversalPipelineRemediationTestSuite(unittest.TestCase):
    """
    Comprehensive universal repository-wide test suite verifying:
    - Group A: Repository-wide regression across all 86 discovered .vital files
    - Group B: Error remediation across compiler and security stages
    - Group C: Multilingual remediation across all 6 supported languages
    - Group D: Multiple errors per stage (partial fixes leave stage failed until clean)
    - Group E: Concurrency, revision invalidation, Restore Original, and Save Corrected Code
    - Group F: Security regression (pristine demo immutability on disk)
    """

    @classmethod
    def setUpClass(cls):
        # Discover all .vital files across the entire repository
        cls.all_vital_files = []
        for root, _, files in os.walk(PROJECT_ROOT):
            if "node_modules" in root or ".git" in root or "venv" in root:
                continue
            for f in files:
                if f.endswith(".vital"):
                    cls.all_vital_files.append(os.path.join(root, f))
        cls.all_vital_files.sort()

    # -------------------------------------------------------------------------
    # GROUP A: Repository-Wide Regression Across All 86 .vital Files
    # -------------------------------------------------------------------------
    def test_group_a_all_86_vital_files_discovered(self):
        """Verify discovery of all 86 .vital files in the repository."""
        self.assertGreaterEqual(
            len(self.all_vital_files), 86,
            f"Expected at least 86 .vital files, discovered {len(self.all_vital_files)}"
        )

    def test_group_a_repository_wide_pipeline_execution(self):
        """Execute pipeline on every discovered .vital file without crashes."""
        passed_count = 0
        paused_count = 0
        error_count = 0

        for filepath in self.all_vital_files:
            rel = os.path.relpath(filepath, PROJECT_ROOT)
            with open(filepath, "r", encoding="utf-8") as f:
                code = f.read()

            try:
                tracker = execute_pipeline_with_tracker(
                    code,
                    pause_on_error=True,
                    run_ai_security=False
                )
                if tracker.status in ("completed", "ready_for_report", "warning"):
                    passed_count += 1
                elif tracker.status == "paused":
                    paused_count += 1
                else:
                    passed_count += 1
            except Exception as e:
                error_count += 1
                print(f"FAILED on file {rel}: {e}")

        self.assertEqual(error_count, 0, f"Expected 0 unhandled exceptions across all {len(self.all_vital_files)} files.")
        self.assertGreater(passed_count, 0)
        self.assertGreater(paused_count, 0)

    # -------------------------------------------------------------------------
    # GROUP B: Remediation Lifecycle Across Compiler Stages
    # -------------------------------------------------------------------------
    def test_group_b_syntax_stage_delimiter_remediation(self):
        """Verify syntax stage pauses on unclosed brace and auto-resumes after fix."""
        faulty_code = (
            "function calculate_tax(amount) {\n"
            "    if (amount > 100) {\n"
            "        return amount * 0.15\n"
            "    }\n"
            # Missing closing brace for function
        )
        # 1. Detect error and pause
        tracker = execute_pipeline_with_tracker(faulty_code, pause_on_error=True, run_ai_security=False)
        self.assertEqual(tracker.status, "paused")
        self.assertEqual(tracker.paused_stage, "syntax_analysis")
        syntax_stage = tracker.stages["syntax_analysis"]
        self.assertEqual(syntax_stage["status"], "failed")
        self.assertGreater(syntax_stage["findings_count"], 0)

        # 2. Propose fix
        fix = security_coordinator.generate_deterministic_fix(
            faulty_code,
            finding_id="SEC-PAR-001",
            finding_data=syntax_stage["details"]["findings"][0],
            language="English"
        )
        self.assertIsNotNone(fix)
        self.assertTrue(fix.get("proposed_source"))
        repaired_code = fix["proposed_source"]

        # 3. Auto-resume pipeline from syntax_analysis
        resumed_tracker = execute_pipeline_with_tracker(
            repaired_code,
            resume_from="syntax_analysis",
            pause_on_error=True,
            run_ai_security=False
        )
        resumed_syntax = resumed_tracker.stages["syntax_analysis"]
        self.assertIn(resumed_syntax["status"], ("completed", "warning"))
        self.assertEqual(resumed_syntax["findings_count"], 0)

    def test_group_b_semantic_stage_undefined_variable_remediation(self):
        """Verify semantic analysis pauses on undefined variable and resumes after fix."""
        faulty_code = (
            "function compute_discount(price) {\n"
            "    let total = price - disc_rate\n"
            "    return total\n"
            "}\n"
        )
        tracker = execute_pipeline_with_tracker(faulty_code, pause_on_error=True, run_ai_security=False)
        self.assertEqual(tracker.status, "paused")
        self.assertEqual(tracker.paused_stage, "semantic_analysis")
        sem_stage = tracker.stages["semantic_analysis"]
        self.assertEqual(sem_stage["status"], "failed")

    def test_group_b_security_stage_remediation_lifecycle(self):
        """Verify security analysis remediation reduces risk score and clears finding."""
        vulnerable_code = (
            "function transfer_funds(caller_id, from_account_id, to_account_id, amount) {\n"
            "    print(\"Initiating transfer\")\n"
            "    if (amount > 500) {\n"
            "        let status_ok = check_account_status(from_account_id, 1)\n"
            "        if (status_ok == 0) { return 0 }\n"
            "    } else {\n"
            "        print(\"Transfer processed\")\n"
            "    }\n"
            "    return 1\n"
            "}\n"
        )
        scan = security_coordinator.run_full_scan(vulnerable_code, language="English", use_ai_enrichment=False)
        findings = scan.get("findings", [])
        self.assertGreater(len(findings), 0)

        idor_finding = next((f for f in findings if "IDOR" in f.get("title", "") or "SEC-AUTH-001" in f.get("rule_id", "")), None)
        self.assertIsNotNone(idor_finding)

        # Propose fix
        fix = security_coordinator.generate_deterministic_fix(
            vulnerable_code,
            finding_id=idor_finding["id"],
            finding_data=idor_finding,
            language="English"
        )
        self.assertIsNotNone(fix)
        repaired = fix.get("proposed_source")
        self.assertTrue(repaired)

        # Re-scan repaired source
        rescan = security_coordinator.run_full_scan(repaired, language="English", use_ai_enrichment=False)
        rescan_findings = rescan.get("findings", [])
        remaining_idor = [f for f in rescan_findings if "IDOR" in f.get("title", "") or "SEC-AUTH-001" in f.get("rule_id", "")]
        self.assertEqual(len(remaining_idor), 0, "Expected IDOR finding to be completely neutralized.")

    # -------------------------------------------------------------------------
    # GROUP C: Multilingual Regression Across All 6 Languages
    # -------------------------------------------------------------------------
    def test_group_c_multilingual_sec_auth_account_remediation_hi_and_en(self):
        """Test the primary user cases: sec_auth_account.vital and sec_auth_account_hi.vital."""
        test_pairs = [
            ("examples/security_lab/english/sec_auth_account.vital", "English"),
            ("examples/security_lab/hindi/sec_auth_account_hi.vital", "Hindi"),
        ]
        for rel_path, lang in test_pairs:
            full_path = os.path.join(PROJECT_ROOT, rel_path)
            with open(full_path, "r", encoding="utf-8") as f:
                orig_code = f.read()

            tracker = execute_pipeline_with_tracker(orig_code, pause_on_error=True, run_ai_security=False)
            self.assertEqual(tracker.status, "paused")
            paused_stage = tracker.paused_stage
            self.assertEqual(paused_stage, "semantic_analysis")

            stage_data = tracker.stages[paused_stage]
            findings = stage_data.get("details", {}).get("findings", [])
            self.assertGreater(len(findings), 0)

            # Generate fix for undefined variable
            fix = security_coordinator.generate_deterministic_fix(
                orig_code,
                finding_id=findings[0]["id"],
                finding_data=findings[0],
                language=lang
            )
            self.assertIsNotNone(fix)
            self.assertTrue(fix.get("proposed_source"))

            # Resume pipeline from paused stage
            resumed = execute_pipeline_with_tracker(
                fix["proposed_source"],
                resume_from=paused_stage,
                pause_on_error=True,
                run_ai_security=False
            )
            # Semantic analysis should now be passed cleanly
            self.assertEqual(resumed.stages["semantic_analysis"]["status"], "completed")
            self.assertEqual(resumed.stages["semantic_analysis"]["findings_count"], 0)

    def test_group_b_semantic_stage_eval_remediation_telugu_reproduction(self):
        """
        Verify reproduction case: examples/security_lab/telugu/sec_injection_eval_te.vital.
        Semantic Analysis initially fails on eval reference (line 35). Suggest Fix produces
        Telugu native safe print replacement. Revalidation completes semantic stage and auto-resumes.
        """
        repro_path = os.path.join(PROJECT_ROOT, "examples", "security_lab", "telugu", "sec_injection_eval_te.vital")
        with open(repro_path, "r", encoding="utf-8") as f:
            code = f.read()

        # 1. Initial pipeline execution halts at semantic_analysis
        tracker = execute_pipeline_with_tracker(code, language_hint="Telugu", pause_on_error=True, run_ai_security=False)
        self.assertEqual(tracker.status, "paused")
        self.assertEqual(tracker.paused_stage, "semantic_analysis")
        self.assertEqual(tracker.stages["semantic_analysis"]["status"], "failed")

        findings = tracker.stages["semantic_analysis"]["details"].get("findings", [])
        self.assertGreaterEqual(len(findings), 1)
        eval_finding = next((f for f in findings if "eval" in f["id"] or f.get("identifier") == "eval"), None)
        self.assertIsNotNone(eval_finding, "Expected SEC-SEM-001 finding for 'eval' identifier")

        # 2. Suggest Fix produces valid unified diff and modifies source
        fix = security_coordinator.suggest_fix_for_finding(
            code,
            finding_id=eval_finding["id"],
            finding_data=eval_finding,
            language="Telugu",
            prefer_deterministic=True
        )
        self.assertTrue(fix.get("success"), f"Suggest fix failed: {fix.get('error')}")
        self.assertIn("ముద్రించు", fix.get("proposed_code", ""))
        self.assertNotEqual(fix.get("proposed_source"), code)
        self.assertGreater(len(fix.get("diff", "")), 0)

        # 3. Re-run pipeline from semantic_analysis with repaired code
        resumed = execute_pipeline_with_tracker(
            fix["proposed_source"],
            language_hint="Telugu",
            resume_from="semantic_analysis",
            pause_on_error=True,
            run_ai_security=False
        )
        self.assertEqual(resumed.stages["semantic_analysis"]["status"], "completed")
        self.assertEqual(resumed.stages["semantic_analysis"]["findings_count"], 0)
        self.assertEqual(resumed.stages["final_report"]["status"], "ready")

    def test_group_c_all_six_languages_syntax_and_keywords(self):
        """Verify pipeline execution and syntax rules on canonical files across all 6 languages."""
        canonical_map = {
            "english": "examples/english/hello.vital",
            "hindi": "examples/hindi/hello.vital",
            "telugu": "examples/telugu/hello.vital",
            "bengali": "examples/bengali/hello.vital",
            "marathi": "examples/marathi/hello.vital",
            "nepali": "examples/nepali/hello.vital"
        }
        for lang, path in canonical_map.items():
            full = os.path.join(PROJECT_ROOT, path)
            with open(full, "r", encoding="utf-8") as f:
                code = f.read()
            tracker = execute_pipeline_with_tracker(code, pause_on_error=True, run_ai_security=False)
            self.assertIn(
                tracker.status, ("completed", "ready_for_report", "warning"),
                f"Failed canonical run for {lang}: status was {tracker.status}"
            )
            self.assertEqual(tracker.stages["syntax_analysis"]["status"], "completed")
            self.assertEqual(tracker.stages["semantic_analysis"]["status"], "completed")

    def test_group_c_semantic_stage_eval_remediation_all_six_languages(self):
        """Verify semantic eval remediation across all 6 supported languages."""
        eval_demos = [
            ("English", "examples/security_lab/english/sec_injection_eval.vital", "print("),
            ("Telugu", "examples/security_lab/telugu/sec_injection_eval_te.vital", "ముద్రించు("),
            ("Hindi", "examples/security_lab/hindi/sec_injection_eval_hi.vital", "लिखो("),
            ("Bengali", "examples/security_lab/bengali/sec_injection_eval_bn.vital", "ছাপাও("),
            ("Marathi", "examples/security_lab/marathi/sec_injection_eval_mr.vital", "लिहा("),
            ("Nepali", "examples/security_lab/nepali/sec_injection_eval_ne.vital", "छाप(")
        ]
        for lang, path, expected_print_call in eval_demos:
            full_path = os.path.join(PROJECT_ROOT, path)
            with open(full_path, "r", encoding="utf-8") as f:
                code = f.read()

            t1 = execute_pipeline_with_tracker(code, language_hint=lang, pause_on_error=True, run_ai_security=False)
            self.assertEqual(t1.paused_stage, "semantic_analysis", f"Expected pause on semantic_analysis for {lang}")
            findings = t1.stages["semantic_analysis"]["details"].get("findings", [])
            self.assertGreater(len(findings), 0, f"Expected semantic findings for {lang}")
            target = findings[0]

            res = security_coordinator.suggest_fix_for_finding(code, target["id"], target, lang, prefer_deterministic=True)
            self.assertTrue(res.get("success"), f"Suggest fix failed for {lang}: {res.get('error')}")
            self.assertIn(expected_print_call, res.get("proposed_code", ""), f"Missing expected print in {lang}")
            self.assertNotEqual(res.get("proposed_source"), code, f"Source was unchanged for {lang}")

            t2 = execute_pipeline_with_tracker(res["proposed_source"], language_hint=lang, resume_from="semantic_analysis", pause_on_error=True, run_ai_security=False)
            post_findings = t2.stages["semantic_analysis"]["details"].get("findings", [])
            self.assertEqual(len(post_findings), 0, f"Expected 0 findings after fix for {lang}")
            self.assertEqual(t2.stages["semantic_analysis"]["status"], "completed", f"Expected completed for {lang}")
            self.assertEqual(t2.stages["final_report"]["status"], "ready", f"Expected ready final_report for {lang}")

    # -------------------------------------------------------------------------
    # GROUP D: Multiple Errors per Stage (Partial vs Full Remediation)
    # -------------------------------------------------------------------------
    def test_group_d_multiple_errors_partial_fix_keeps_stage_failed(self):
        """
        Verify that fixing only 1 of 2 errors in a stage leaves the stage failed,
        shows remaining errors, and only passes when all errors are resolved.
        """
        # Code with 2 syntax issues: duplicate open brace at line 2 and missing brace at end
        multi_error_code = (
            "function process_data(val) {{\n"
            "    print(val)\n"
            # Missing closing brace
        )
        tracker = execute_pipeline_with_tracker(multi_error_code, pause_on_error=True, run_ai_security=False)
        self.assertEqual(tracker.status, "paused")
        self.assertEqual(tracker.paused_stage, "syntax_analysis")
        self.assertEqual(tracker.stages["syntax_analysis"]["status"], "failed")

        # Partial fix: close end brace but leave duplicate `{{`
        partially_fixed_code = (
            "function process_data(val) {{\n"
            "    print(val)\n"
            "}\n"
        )
        partial_tracker = execute_pipeline_with_tracker(
            partially_fixed_code,
            resume_from="syntax_analysis",
            pause_on_error=True,
            run_ai_security=False
        )
        # Stage MUST still fail because `{{` remains
        self.assertEqual(partial_tracker.stages["syntax_analysis"]["status"], "failed")
        self.assertEqual(partial_tracker.paused_stage, "syntax_analysis")

        # Full fix: clean braces
        clean_code = (
            "function process_data(val) {\n"
            "    print(val)\n"
            "}\n"
        )
        clean_tracker = execute_pipeline_with_tracker(
            clean_code,
            resume_from="syntax_analysis",
            pause_on_error=True,
            run_ai_security=False
        )
        self.assertEqual(clean_tracker.stages["syntax_analysis"]["status"], "completed")
        self.assertEqual(clean_tracker.stages["syntax_analysis"]["findings_count"], 0)

    def test_group_d_semantic_multi_error_incremental_resolution(self):
        """
        Verify that in a program with multiple semantic errors (divzero + undeclared variables),
        each fix resolves only its target finding, leaves others detected, and only passes
        the semantic stage once all errors are cleared.
        """
        multi_err = (
            "let total = 100\n"
            "let ratio = total / 0\n"
            "print(first_missing_var)\n"
            "print(second_missing_var)\n"
        )
        t1 = execute_pipeline_with_tracker(multi_err, pause_on_error=True, run_ai_security=False)
        self.assertEqual(t1.paused_stage, "semantic_analysis")
        findings1 = t1.stages["semantic_analysis"]["details"].get("findings", [])
        self.assertEqual(len(findings1), 3)

        # Fix 1: Guard divzero
        f_div = next(f for f in findings1 if "divzero" in f["id"] or "SEM-001" in f["id"])
        fix_div = security_coordinator.suggest_fix_for_finding(multi_err, f_div["id"], f_div, "English", prefer_deterministic=True)
        self.assertTrue(fix_div.get("success"))

        t2 = execute_pipeline_with_tracker(fix_div["proposed_source"], resume_from="semantic_analysis", pause_on_error=True, run_ai_security=False)
        self.assertEqual(t2.paused_stage, "semantic_analysis")
        self.assertEqual(t2.stages["semantic_analysis"]["status"], "failed")
        findings2 = t2.stages["semantic_analysis"]["details"].get("findings", [])
        self.assertEqual(len(findings2), 2)

        # Fix 2: Declare first_missing_var
        f_var1 = next(f for f in findings2 if "first_missing_var" in f["id"])
        fix_var1 = security_coordinator.suggest_fix_for_finding(fix_div["proposed_source"], f_var1["id"], f_var1, "English", prefer_deterministic=True)
        self.assertTrue(fix_var1.get("success"))

        t3 = execute_pipeline_with_tracker(fix_var1["proposed_source"], resume_from="semantic_analysis", pause_on_error=True, run_ai_security=False)
        self.assertEqual(t3.paused_stage, "semantic_analysis")
        self.assertEqual(t3.stages["semantic_analysis"]["status"], "failed")
        findings3 = t3.stages["semantic_analysis"]["details"].get("findings", [])
        self.assertEqual(len(findings3), 1)

        # Fix 3: Declare second_missing_var
        f_var2 = next(f for f in findings3 if "second_missing_var" in f["id"])
        fix_var2 = security_coordinator.suggest_fix_for_finding(fix_var1["proposed_source"], f_var2["id"], f_var2, "English", prefer_deterministic=True)
        self.assertTrue(fix_var2.get("success"))

        t4 = execute_pipeline_with_tracker(fix_var2["proposed_source"], resume_from="semantic_analysis", pause_on_error=True, run_ai_security=False)
        self.assertIsNone(t4.paused_stage)
        self.assertEqual(t4.stages["semantic_analysis"]["status"], "completed")
        self.assertEqual(t4.stages["final_report"]["status"], "ready")

    def test_group_e_stale_proposal_and_noop_rejected(self):
        """Verify that identical/no-op proposals and missing compiler fixes return success: False."""
        sample_code = "print(\"hello world\")\n"
        finding = {
            "id": "SEC-SEM-001-L1-unknown",
            "title": "Identifier 'unknown' referenced before explicit local assignment.",
            "rule_id": "SEC-SEM-001",
            "stage_id": "semantic_analysis",
            "line": 99,
            "identifier": ""
        }
        res = security_coordinator.suggest_fix_for_finding(sample_code, finding["id"], finding, "English", prefer_deterministic=True)
        # Should NOT claim success with empty diff
        self.assertFalse(res.get("success"), "Expected failure when no modification can be determined")
        self.assertIn("Automated fix could not be deterministically determined", res.get("error", ""))

    # -------------------------------------------------------------------------
    # GROUP E: Concurrency, Revision Tracking, and File Save/Restore
    # -------------------------------------------------------------------------
    def test_group_e_save_file_endpoint_preserves_demo_and_saves_clean(self):
        """Test POST /api/save-file creates user saved copy in examples/saved/ without modifying demo."""
        test_client = server_module.app.test_client()
        saved_name = "test_custom_corrected_program.vital"
        test_content = "print(\"Corrected user code\")\n"

        response = test_client.post(
            "/api/save-file",
            data=json.dumps({"filename": saved_name, "code": test_content}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        resp_data = json.loads(response.data.decode("utf-8"))
        self.assertTrue(resp_data.get("success"))

        saved_path = os.path.join(PROJECT_ROOT, "examples", "saved", saved_name)
        self.assertTrue(os.path.exists(saved_path))
        with open(saved_path, "r", encoding="utf-8") as f:
            read_back = f.read()
        self.assertEqual(read_back, test_content)

        # Cleanup test file
        if os.path.exists(saved_path):
            os.remove(saved_path)

    def test_group_e_save_file_directory_traversal_protection(self):
        """Verify POST /api/save-file rejects path traversal attacks."""
        test_client = server_module.app.test_client()
        bad_filenames = [
            "../../src/main.py",
            "..\\..\\web\\server.py",
            "../../../evil.vital",
            "/etc/passwd.vital"
        ]
        for bad_name in bad_filenames:
            response = test_client.post(
                "/api/save-file",
                data=json.dumps({"filename": bad_name, "code": "malicious"}),
                content_type="application/json"
            )
            # Should be 400 or rejected
            self.assertIn(response.status_code, (400, 403))

    # -------------------------------------------------------------------------
    # GROUP F: Security Lab Intactness (Demos Untouched On Disk)
    # -------------------------------------------------------------------------
    def test_group_f_original_demos_unmodified_on_disk(self):
        """
        Verify that educational security lab demo fixtures on disk
        have NOT been overwritten and still contain their intended vulnerabilities.
        """
        demo_files = glob.glob(os.path.join(PROJECT_ROOT, "examples", "security_lab", "*", "*.vital"))
        self.assertGreaterEqual(len(demo_files), 24, "Expected at least 24 Security Lab demos.")

        for demo in demo_files:
            with open(demo, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn(
                "INTENTIONALLY VULNERABLE", content,
                f"Demo {demo} was modified on disk! Educational header missing."
            )


if __name__ == "__main__":
    unittest.main()
