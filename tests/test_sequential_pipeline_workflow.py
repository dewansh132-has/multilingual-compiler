"""
Comprehensive Automated Test Suite for VITAL Sequential Compiler Pipeline,
Interactive Error Remediation, Output Gating, and Final Report Workflow.

Verifies:
1. Sequential stage definitions and dependencies across 14 canonical stages.
2. Progressive execution halting on errors and blocking downstream stages.
3. Individual Suggest Fix workflow leaving disk fixtures untouched.
4. Multi-error remediation one by one.
5. Revalidation and pipeline resumption after fix application.
6. Right-hand output gating and explicit Final Report completion gate.
7. Multilingual execution fidelity across English, Hindi, Telugu, Bengali, Marathi, Nepali.
8. UI templates, stepper placement, overlay viewport sizing, and continuous vertical scrolling.
"""

import os
import re
import json
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from web.server import app
from web.pipeline_tracker import (
    STAGE_DEFINITIONS,
    PipelineRunTracker,
    execute_pipeline_with_tracker
)
from web.security_analyzer import security_coordinator


class TestSequentialPipelineWorkflow(unittest.TestCase):

    def setUp(self):
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def test_01_canonical_14_stages_defined_in_correct_order(self):
        """Task 1.1: Verify all 14 canonical compiler stages are defined in correct dependency order."""
        expected_stage_ids = [
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
        actual_stage_ids = [st["id"] for st in STAGE_DEFINITIONS]
        self.assertEqual(actual_stage_ids, expected_stage_ids)

        # Verify Optimization stage is mandatory and applicable
        opt_stage = next(s for s in STAGE_DEFINITIONS if s["id"] == "optimization")
        self.assertTrue(opt_stage["applicable"], "Optimization must be flagged as mandatory / applicable in VITAL architecture")

    def test_02_sequential_halting_on_syntax_error(self):
        """Task 1.2 & 1.3: Pipeline halts on syntax error, marks error stage failed and downstream blocked."""
        # Intentionally malformed syntax with unclosed delimiter
        malformed_code = 'let x = 10\nif (x > 5) {\n    print("Missing closing brace")\n'
        tracker = PipelineRunTracker()
        execute_pipeline_with_tracker(
            source_code=malformed_code,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            pause_on_error=True
        )

        res = tracker.to_dict()
        stages_by_id = {s["id"]: s for s in res["stages"]}

        # 1. Source and Lexer must have passed
        self.assertEqual(stages_by_id["source_input"]["status"], "completed")
        self.assertEqual(stages_by_id["lexical_analysis"]["status"], "completed")

        # 2. Syntax Analysis must have failed
        self.assertEqual(stages_by_id["syntax_analysis"]["status"], "failed")
        self.assertGreater(stages_by_id["syntax_analysis"]["findings_count"], 0)

        # 3. AST and all downstream dependent stages must be blocked (NOT passed, NOT completed)
        downstream_stages = [
            "ast_construction", "semantic_analysis", "symbol_table",
            "ir_generation", "code_generation", "code_validation",
            "security_analysis", "ai_security_analysis", "sandbox_execution", "final_report"
        ]
        for sid in downstream_stages:
            self.assertEqual(
                stages_by_id[sid]["status"],
                "blocked",
                f"Stage {sid} must be marked 'blocked' after syntax failure, but was {stages_by_id[sid]['status']}"
            )

        # 4. Pipeline state must be paused
        self.assertTrue(res["is_paused"])
        self.assertEqual(res["paused_stage"], "syntax_analysis")

    def test_03_individual_suggest_fix_preserves_disk_file_untouched(self):
        """Task 4.10 & Task 7.22: Working buffer remediation leaves disk demo file byte-for-byte untouched."""
        demo_path = os.path.join(PROJECT_ROOT, "examples", "security_lab", "english", "sec_auth_account.vital")
        if not os.path.exists(demo_path):
            self.skipTest(f"Demo file {demo_path} not found")

        with open(demo_path, "rb") as f:
            original_bytes = f.read()

        original_text = original_bytes.decode("utf-8")
        # Run scan to locate finding
        scan_res = security_coordinator.run_full_scan(original_text, language="English", use_ai_enrichment=False)
        findings = scan_res.get("findings", [])
        self.assertGreater(len(findings), 0, "Demo must produce at least one security finding")

        target_finding = findings[0]
        finding_id = target_finding["id"] if isinstance(target_finding, dict) else target_finding.id
        finding_dict = target_finding if isinstance(target_finding, dict) else target_finding.to_dict()

        # Request individual deterministic fix
        fix_res = security_coordinator.suggest_fix_for_finding(
            source_code=original_text,
            finding_id=finding_id,
            finding_data=finding_dict,
            language="English",
            prefer_deterministic=True,
            request_ai=False
        )
        self.assertTrue(fix_res["success"])
        self.assertIn("diff", fix_res)
        self.assertTrue(fix_res["is_deterministic"])

        # Proposed source is an in-memory string
        proposed_source = fix_res["proposed_source"]
        self.assertNotEqual(proposed_source, original_text)

        # Re-check the physical disk file
        with open(demo_path, "rb") as f:
            after_bytes = f.read()

        self.assertEqual(original_bytes, after_bytes, "Disk demo file was modified! Must remain byte-for-byte untouched.")

    def test_04_multi_error_individual_remediation(self):
        """Task 3.9 & 4.15: Fixing one error marks it resolved while remaining errors stay active."""
        demo_path = os.path.join(PROJECT_ROOT, "examples", "security_lab", "english", "sec_auth_account.vital")
        if not os.path.exists(demo_path):
            self.skipTest("Demo file not found")

        with open(demo_path, "r", encoding="utf-8") as f:
            code = f.read()

        scan = security_coordinator.run_full_scan(code, language="English", use_ai_enrichment=False)
        initial_findings = scan.get("findings", [])
        self.assertGreaterEqual(len(initial_findings), 2, "sec_auth_account must produce multiple findings (IDOR and Auth Bypass)")

        first_finding = initial_findings[0]
        finding_id = first_finding["id"] if isinstance(first_finding, dict) else first_finding.id
        finding_dict = first_finding if isinstance(first_finding, dict) else first_finding.to_dict()

        fix_res = security_coordinator.suggest_fix_for_finding(
            source_code=code,
            finding_id=finding_id,
            finding_data=finding_dict,
            language="English",
            prefer_deterministic=True
        )
        self.assertTrue(fix_res["success"])

        # Verify repair of only the first finding
        verif = security_coordinator.verify_repair(
            original_source=code,
            repaired_source=fix_res["proposed_source"],
            language="English",
            target_finding_id=finding_id
        )
        self.assertTrue(verif["success"])

        # The target finding should be resolved, and the other finding should remain active
        resolved_ids = [rf["id"] for rf in verif.get("resolved_findings", [])]
        remaining_ids = [rf["id"] for rf in verif.get("remaining_findings", [])]

        self.assertIn(finding_id, resolved_ids, "Target finding must be in resolved findings list")
        self.assertGreater(len(remaining_ids), 0, "Remaining findings must remain active for individual fixing")

    def test_05_revalidation_and_pipeline_resumption(self):
        """Task 1.2 & 4.15: Applying a valid fix allows the pipeline to resume cleanly."""
        broken_code = 'let count = 3\nif (count > 0) {\n    print("Testing resume")\n' # missing closing brace
        tracker = PipelineRunTracker()
        execute_pipeline_with_tracker(broken_code, pause_on_error=True, tracker=tracker)
        self.assertEqual(tracker.to_dict()["stages"][2]["status"], "failed") # syntax failed

        # Fix the syntax error by supplying matching closing brace
        fixed_code = broken_code + "}\n"
        resumed_tracker = PipelineRunTracker()
        execute_pipeline_with_tracker(fixed_code, pause_on_error=True, tracker=resumed_tracker)

        resumed_dict = resumed_tracker.to_dict()
        stages_by_id = {s["id"]: s for s in resumed_dict["stages"]}

        # Syntax must now be completed
        self.assertEqual(stages_by_id["syntax_analysis"]["status"], "completed")
        # AST, Semantics, Symbol Table, IR, Code Gen, Security, Sandbox must have completed
        self.assertEqual(stages_by_id["ast_construction"]["status"], "completed")
        self.assertEqual(stages_by_id["semantic_analysis"]["status"], "completed")
        self.assertEqual(stages_by_id["symbol_table"]["status"], "completed")
        self.assertEqual(stages_by_id["ir_generation"]["status"], "completed")
        self.assertEqual(stages_by_id["code_generation"]["status"], "completed")
        self.assertEqual(stages_by_id["sandbox_execution"]["status"], "completed")

        # Stage 14 Final Report must be ready for report generation or completed
        self.assertTrue(resumed_dict["is_ready_for_report"] or stages_by_id["final_report"]["status"] in ("ready", "completed"))
        self.assertIn(stages_by_id["final_report"]["status"], ("ready", "completed"))

    def test_06_final_report_completion_gate_and_output_gating(self):
        """Task 5 & Task 6: Final report generates only when prerequisites pass, unlocking output artifacts."""
        valid_code = 'let message = "Testing Completion Gate"\nprint(message)\n'

        # Attempt to generate report on broken code must be rejected with HTTP 400
        broken_code = 'let bad = (1 + 2\n'
        resp_bad = self.client.post('/api/pipeline/generate-report', json={"code": broken_code, "language": "English"})
        self.assertEqual(resp_bad.status_code, 400)
        bad_json = json.loads(resp_bad.get_data(as_text=True))
        self.assertFalse(bad_json["success"])
        self.assertIn("Syntax Analysis stage failed", bad_json["error"])

        # Generating report on valid code must succeed and return complete artifacts
        resp_good = self.client.post('/api/pipeline/generate-report', json={"code": valid_code, "language": "English"})
        self.assertEqual(resp_good.status_code, 200)
        good_json = json.loads(resp_good.get_data(as_text=True))
        self.assertTrue(good_json["success"])
        self.assertIn("artifacts", good_json)
        artifacts = good_json["artifacts"]

        # Verify all essential output artifacts are present
        self.assertIn("output", artifacts)
        self.assertIn("ir_code", artifacts)
        self.assertIn("ast_log", artifacts)
        self.assertIn("symbol_table", artifacts)
        self.assertIn("lexer_log", artifacts)
        self.assertIn("parser_log", artifacts)
        self.assertIn("Testing Completion Gate", artifacts["output"])

    def test_07_multilingual_pipeline_execution(self):
        """Task 7.23: Sequential pipeline executes across all 6 supported languages."""
        multilingual_samples = [
            ("English", 'let x = 10\nprint(x)'),
            ("Hindi", 'मानो संख्या = 15\nलिखो(संख्या)'),
            ("Telugu", 'అనుకో సంఖ్య = 20\nరాయి(సంఖ్య)'),
            ("Bengali", 'ধরো সংখ্যা = 25\nছাপাও(সংখ্যা)'),
            ("Marathi", 'घ्या संख्या = 30\nलिहा(संख्या)'),
            ("Nepali", 'मान सङ्ख्या = 35\nछाप(सङ्ख्या)')
        ]

        for lang, code in multilingual_samples:
            tracker = PipelineRunTracker()
            execute_pipeline_with_tracker(
                source_code=code,
                language_hint=lang,
                run_ai_security=False,
                tracker=tracker,
                pause_on_error=False
            )
            data = tracker.to_dict()
            self.assertTrue(
                data["success"],
                f"Pipeline execution failed for language {lang}: {data.get('artifacts', {}).get('output')}"
            )
            self.assertEqual(len(data["stages"]), 14, f"All 14 stages must execute for {lang}")
            self.assertEqual(data["stages"][0]["status"], "completed") # Source input
            self.assertEqual(data["stages"][1]["status"], "completed") # Lexer
            self.assertEqual(data["stages"][2]["status"], "completed") # Parser
            self.assertEqual(data["stages"][3]["status"], "completed") # AST
            self.assertEqual(data["stages"][6]["status"], "completed") # IR
            self.assertEqual(data["stages"][12]["status"], "completed") # Sandbox

    def test_08_ui_templates_stepper_and_overlay_specs(self):
        """Task 1.1, Task 2.5, Task 2.7, Task 5.16: Verify HTML/CSS architecture constraints."""
        # Read index.html
        with open(os.path.join(PROJECT_ROOT, "web", "templates", "index.html"), "r", encoding="utf-8") as f:
            html = f.read()

        # 1. Stepper row is present above workspace
        self.assertIn('id="pipeline-stepper"', html)
        self.assertIn('class="pipeline-progress-container"', html)

        # 2. Output waiting state is present and output tabs start hidden
        self.assertIn('id="output-waiting-state"', html)
        self.assertIn('Compiler Artifacts Awaiting Completion', html)
        self.assertIn('id="output-tabs-bar" style="display: none;"', html)
        self.assertIn('id="output-content-area" style="display: none;"', html)

        # Read ide.css
        with open(os.path.join(PROJECT_ROOT, "web", "static", "css", "ide.css"), "r", encoding="utf-8") as f:
            css = f.read()

        # 3. Status blocked and status ready CSS rules exist
        self.assertIn('.stepper-step.status-blocked', css)
        self.assertIn('.stepper-step.status-ready', css)

        # 4. Floating overlay has proper responsive viewport width (40-48% on desktop)
        self.assertIn('width: clamp(420px, 46vw, 760px);', css)
        self.assertIn('max-height: 85vh;', css)

        # 5. Continuous vertical scrollbar: overlay scroll body has overflow-y: auto
        self.assertIn('.stage-overlay-scroll-body', css)
        self.assertIn('overflow-y: auto;', css)


if __name__ == '__main__':
    unittest.main()
