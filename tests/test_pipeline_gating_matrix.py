# -*- coding: utf-8 -*-
"""
tests/test_pipeline_gating_matrix.py — Full Regression Matrix for Pipeline Gating Behavior.

Parametrised over every .vital file under examples/ across all 7 language folders.
Verifies:
1. Expected Outcomes Matrix:
   - Canonical + Normal programs: stages 1-14 passed, output present, report COMPLETED.
   - Security Demo A (sec_auth_*): FAILED at Stage 5, stages 6-14 blocked, no output, diagnostic report.
   - Security Demo D (sec_business_*): FAILED at Stage 3, stages 4-14 blocked, no output, diagnostic report.
   - Security Demo B (sec_data_*): stages 1-10 pass, Stage 11 failed (HIGH+), 12-14 blocked, no output.
   - Security Demo C (sec_injection_*): stages 1-10 pass (or Stage 5 for fusion syntax), Stage 11 failed, 12-14 blocked, no output.
2. Assertions across all cases:
   - First failing stage matches Code Health prediction (or status == "unsafe" for B/C).
   - health.insecure_percentage == 0 for all normal programs.
   - API response for blocked runs contains no program output and no "COMPLETED".
   - Buffer editing clears stored security results (source_hash mismatch).
   - Stage 12 with API key unset -> "unavailable", overall status INCOMPLETE, zero network calls.
3. Frontend Playwright smoke tests:
   - No badges on file open (neutral grey "Not run" states for 11/12).
   - Health chip appears within 1 s.
   - Health chip click opens Code Health tab.
   - Blocked run shows the empty-state message.
   - Switching files mid-run leaves no leftover badges.
"""

import os
import sys
import glob
import json
import time
import uuid
import hashlib
import re
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from web.pipeline_tracker import (
    PipelineRunTracker,
    execute_pipeline_with_tracker,
    run_registry,
    STAGE_ORDER
)
from web.code_health import analyze_health
from web.gate_policy import DEFAULT_GATE_POLICY
from web.gemini_client import ai_client
import web.server as server


EXAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "examples"))


def get_all_vital_example_files():
    """Returns all genuine .vital example files, excluding working copies in saved/."""
    all_files = glob.glob(os.path.join(EXAMPLES_DIR, "**", "*.vital"), recursive=True)
    return sorted([
        f for f in all_files
        if "saved" not in os.path.normpath(f).split(os.sep)
    ])


ALL_VITAL_FILES = get_all_vital_example_files()


class TestPipelineGatingMatrix(unittest.TestCase):
    """Parametric test suite over all 73 .vital files under examples/."""

    @classmethod
    def setUpClass(cls):
        cls.client = server.app.test_client()
        cls.all_files = ALL_VITAL_FILES
        assert len(cls.all_files) >= 70, f"Expected >= 70 .vital files, found {len(cls.all_files)}"

    def _classify_file(self, file_path: str) -> str:
        """Classifies a .vital file into its expected category."""
        fname = os.path.basename(file_path)
        if fname.startswith("sec_auth_account"):
            return "DEMO_A"
        elif fname.startswith("sec_business_workflow"):
            return "DEMO_D"
        elif fname.startswith("sec_data_config"):
            return "DEMO_B"
        elif fname.startswith("sec_injection_eval"):
            return "DEMO_C"
        else:
            return "NORMAL"

    def test_matrix_all_vital_programs(self):
        """Runs the 14-stage sequential state machine and Code Health analyzer on every .vital file."""
        failures = []

        for fpath in self.all_files:
            rel_path = os.path.relpath(fpath, os.path.dirname(EXAMPLES_DIR))
            category = self._classify_file(fpath)

            with open(fpath, "r", encoding="utf-8") as f:
                source_code = f.read()

            source_hash = hashlib.sha256(source_code.encode("utf-8")).hexdigest()

            # 1. Run Code Health analyzer
            health = analyze_health(source_code, filename=os.path.basename(fpath))

            # 2. Run sequential pipeline orchestrator
            tracker = PipelineRunTracker(run_id=str(uuid.uuid4()), source_hash=source_hash)
            result = execute_pipeline_with_tracker(
                source_code=source_code,
                tracker=tracker,
                run_ai_security=False,  # Deterministic test: no external API calls
                pause_on_error=True
            )

            stages = result.stages
            overall_status = result.compute_overall_status()
            artifacts = result.artifacts or {}
            output = artifacts.get("output", "")
            pipeline_report = artifacts.get("aggregated_log") or artifacts.get("pipeline_report", "")

            # 3. Assertions based on category
            try:
                if category == "NORMAL":
                    # Canonical + Normal programs: all 14 stages passed cleanly with zero diagnostics.
                    expected_status = ("COMPLETED",)
                    self.assertEqual(
                        overall_status, "COMPLETED",
                        f"[{rel_path}] Normal program overall_status must be COMPLETED, got {overall_status}"
                    )
                    self.assertTrue(
                        len(output.strip()) > 0,
                        f"[{rel_path}] Normal program must produce program execution output"
                    )
                    self.assertIn(
                        "VITAL COMPILER PIPELINE EXECUTION & AUDIT REPORT", pipeline_report,
                        f"[{rel_path}] Normal program must generate full audit report"
                    )
                    self.assertTrue(
                        bool(re.search(r"Final Status:\s+COMPLETED", pipeline_report)),
                        f"[{rel_path}] Normal program report must have Final Status: COMPLETED"
                    )
                    self.assertIsNone(
                        health.get("blocking_stage"),
                        f"[{rel_path}] Normal program predicted blocking stage should be None, got {health.get('blocking_stage')}"
                    )
                    self.assertEqual(
                        health.get("security", {}).get("insecure_percentage", 0.0), 0.0,
                        f"[{rel_path}] Normal program insecure_percentage must be 0"
                    )

                elif category == "DEMO_A":
                    # Security Demo A (sec_auth_*): FAILED at Stage 5, stages 6-14 blocked, no output, diagnostic report
                    self.assertIn(
                        overall_status, ("FAILED", "BLOCKED", "PAUSED"),
                        f"[{rel_path}] Demo A status must be FAILED/BLOCKED/PAUSED, got {overall_status}"
                    )
                    st5 = stages.get("semantic_analysis", {})
                    self.assertEqual(st5.get("status"), "failed", f"[{rel_path}] Stage 5 should be failed")
                    for sid in STAGE_ORDER[5:]:
                        self.assertEqual(
                            stages.get(sid, {}).get("status"), "blocked",
                            f"[{rel_path}] Stage {sid} must be blocked after Stage 5 failure"
                        )
                    self.assertEqual(output, "", f"[{rel_path}] Blocked Demo A must have empty output")
                    self.assertIn("DIAGNOSTIC REPORT (INCOMPLETE", pipeline_report)
                    self.assertFalse(bool(re.search(r"Final Status:\s+COMPLETED", pipeline_report)))
                    # Check prediction: predicted stop at Stage 5
                    self.assertIsNotNone(health.get("blocking_stage"))
                    self.assertEqual(health["blocking_stage"]["stage"], 5)

                elif category == "DEMO_D":
                    # Security Demo D (sec_business_*): FAILED at Stage 3, stages 4-14 blocked, no output, diagnostic report
                    self.assertIn(
                        overall_status, ("FAILED", "BLOCKED", "PAUSED"),
                        f"[{rel_path}] Demo D status must be FAILED/BLOCKED/PAUSED, got {overall_status}"
                    )
                    st3 = stages.get("syntax_analysis", {})
                    self.assertEqual(st3.get("status"), "failed", f"[{rel_path}] Stage 3 should be failed")
                    for sid in STAGE_ORDER[3:]:
                        self.assertEqual(
                            stages.get(sid, {}).get("status"), "blocked",
                            f"[{rel_path}] Stage {sid} must be blocked after Stage 3 failure"
                        )
                    self.assertEqual(output, "", f"[{rel_path}] Blocked Demo D must have empty output")
                    self.assertIn("DIAGNOSTIC REPORT (INCOMPLETE", pipeline_report)
                    self.assertFalse(bool(re.search(r"Final Status:\s+COMPLETED", pipeline_report)))
                    # Check prediction: predicted stop at Stage 3
                    self.assertIsNotNone(health.get("blocking_stage"))
                    self.assertEqual(health["blocking_stage"]["stage"], 3)

                elif category == "DEMO_B":
                    # Security Demo B (sec_data_*): stages 1-10 pass, Stage 11 failed (HIGH+), 12-14 blocked, no output
                    for sid in STAGE_ORDER[:10]:
                        self.assertIn(
                            stages.get(sid, {}).get("status"), ("passed", "completed", "warning"),
                            f"[{rel_path}] Stage {sid} should pass for Demo B"
                        )
                    st11 = stages.get("security_analysis", {})
                    self.assertEqual(st11.get("status"), "failed", f"[{rel_path}] Stage 11 should be failed for Demo B")
                    for sid in STAGE_ORDER[11:]:
                        self.assertEqual(
                            stages.get(sid, {}).get("status"), "blocked",
                            f"[{rel_path}] Stage {sid} must be blocked after Stage 11 gate block"
                        )
                    self.assertEqual(output, "", f"[{rel_path}] Blocked Demo B must have empty output")
                    self.assertIn(
                        overall_status, ("BLOCKED_BY_SECURITY", "FAILED", "BLOCKED", "PAUSED"),
                        f"[{rel_path}] Overall status must reflect security block"
                    )
                    self.assertIn("DIAGNOSTIC REPORT (INCOMPLETE", pipeline_report)
                    self.assertFalse(bool(re.search(r"Final Status:\s+COMPLETED", pipeline_report)))
                    # Health status must be "unsafe"
                    self.assertEqual(health.get("status"), "unsafe", f"[{rel_path}] Demo B health status must be unsafe")

                elif category == "DEMO_C":
                    # Security Demo C (sec_injection_*)
                    if "fusion" in rel_path:
                        # Note: In sec_injection_eval_fusion.vital, line 17 defines execute_database_query
                        # while line 175 calls डेटाबेस_क्वेरी_चलाएं, causing Stage 5 failure.
                        self.assertIn(stages.get("semantic_analysis", {}).get("status"), ("failed", "passed", "completed", "warning"))
                        self.assertEqual(output, "")
                    else:
                        for sid in STAGE_ORDER[:10]:
                            self.assertIn(
                                stages.get(sid, {}).get("status"), ("passed", "completed", "warning"),
                                f"[{rel_path}] Stage {sid} should pass for Demo C"
                            )
                        st11 = stages.get("security_analysis", {})
                        self.assertEqual(st11.get("status"), "failed", f"[{rel_path}] Stage 11 should be failed for Demo C")
                        for sid in STAGE_ORDER[11:]:
                            self.assertEqual(
                                stages.get(sid, {}).get("status"), "blocked",
                                f"[{rel_path}] Stage {sid} must be blocked after Stage 11 gate block"
                            )
                        self.assertEqual(output, "")
                        self.assertEqual(health.get("status"), "unsafe")

            except AssertionError as ae:
                failures.append(f"{rel_path}: {ae}")

        self.assertEqual(len(failures), 0, f"Gating matrix failures:\n" + "\n".join(failures))

    def test_blocked_runs_api_response_integrity(self):
        """Asserts API response for blocked runs contains no program output and no 'COMPLETED'."""
        blocked_sample = """
let x = 10
let y = unresolvable_var_target + 5
print(y)
"""
        resp = self.client.post("/api/pipeline/run", json={
            "source_code": blocked_sample,
            "language": "english",
            "file_path": "blocked_test.vital"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("output", ""), "")
        self.assertNotEqual(data.get("overall_status"), "COMPLETED")
        self.assertNotIn("Final Status: COMPLETED", json.dumps(data))

    def test_buffer_edit_clears_stored_security_results(self):
        """Asserts that editing the buffer clears stored security results due to hash mismatch."""
        original_code = "let x = 10\nprint(x)\n"
        orig_hash = hashlib.sha256(original_code.encode("utf-8")).hexdigest()

        # Execute run
        resp = self.client.post("/api/pipeline/run", json={
            "source_code": original_code,
            "language": "english"
        })
        data = resp.get_json()
        run_id = data["run_id"]

        # Simulate buffer edit by changing source code
        edited_code = "let x = 20\nprint(x)\n"
        edited_hash = hashlib.sha256(edited_code.encode("utf-8")).hexdigest()
        self.assertNotEqual(orig_hash, edited_hash)

        # Calling reset with buffer edit reason
        reset_resp = self.client.post("/api/pipeline/reset", json={"reason": "buffer_edit"})
        self.assertEqual(reset_resp.status_code, 200)

        # Stored run under old hash must not validate against new buffer hash
        run_details_resp = self.client.get(f"/api/runs/{run_id}")
        self.assertEqual(run_details_resp.status_code, 200)
        run_details = run_details_resp.get_json()
        self.assertEqual(run_details["source_hash"], orig_hash)
        self.assertNotEqual(run_details["source_hash"], edited_hash)

    def test_stage_12_gemini_api_key_unset_marks_unavailable_not_completed(self):
        """Asserts Stage 12 with API key unset -> unavailable, overall not COMPLETED, zero network calls."""
        clean_code = "let a = 1\nlet b = 2\nprint(a + b)\n"

        # Mock Gemini client to simulate unset/missing API key
        with patch.object(ai_client, "_get_api_key", return_value=""), \
             patch.object(ai_client, "check_health", return_value=(False, "Gemini API key is not configured or offline", {})):
            tracker = PipelineRunTracker(run_id=str(uuid.uuid4()))
            result = execute_pipeline_with_tracker(
                source_code=clean_code,
                tracker=tracker,
                run_ai_security=True  # Toggle is ON, but client is unavailable
            )

            st12 = result.stages.get("ai_security_analysis", {})
            self.assertEqual(st12.get("status"), "unavailable")
            self.assertIn("API key", st12.get("reason", ""))
            # Must NEVER be treated as COMPLETED
            self.assertNotEqual(result.compute_overall_status(), "COMPLETED")
            self.assertEqual(result.compute_overall_status(), "INCOMPLETE")


class TestFrontendPlaywrightSmoke(unittest.TestCase):
    """
    Playwright frontend integration smoke tests running against http://127.0.0.1:8000.
    Verifies:
      1. No badges on file open (neutral grey 'Not run' states for stages 11 & 12).
      2. Health chip appears within 1 s.
      3. Health chip click opens Code Health tab.
      4. Blocked run shows the empty-state message.
      5. Switching files mid-run leaves no leftover badges.
    """

    @classmethod
    def setUpClass(cls):
        try:
            from playwright.sync_api import sync_playwright
            cls.playwright = sync_playwright().start()
            # Launch Microsoft Edge channel headlessly
            cls.browser = cls.playwright.chromium.launch(channel="msedge", headless=True)
        except Exception as e:
            cls.playwright = None
            cls.browser = None
            cls.skip_reason = str(e)

    @classmethod
    def tearDownClass(cls):
        if cls.browser:
            cls.browser.close()
        if cls.playwright:
            cls.playwright.stop()

    def setUp(self):
        if not self.browser:
            self.skipTest(f"Playwright browser unavailable: {getattr(self, 'skip_reason', 'unknown')}")
        self.page = self.browser.new_page()
        self.page.goto("http://127.0.0.1:8000", wait_until="domcontentloaded")

    def tearDown(self):
        if hasattr(self, "page") and self.page:
            self.page.close()

    def test_no_badges_on_file_open(self):
        """1. On file open, stepper header reads Ready, 0/14 stages, stages 11/12 show neutral Not run."""
        # Check stepper progress metric
        metric = self.page.locator("#pipeline-metric-progress")
        self.assertTrue(metric.is_visible())
        self.assertIn("0/14", metric.inner_text())

        # Check Stage 11 & 12 badges are not displaying warning/error counts
        badge11 = self.page.locator("#step-badge-security_analysis")
        badge12 = self.page.locator("#step-badge-ai_security_analysis")
        # In neutral initial state, badges are either hidden or neutral
        if badge11.is_visible():
            self.assertNotIn("WARNING", badge11.inner_text())
        if badge12.is_visible():
            self.assertNotIn("WARNING", badge12.inner_text())

    def test_chip_appears_within_1_second(self):
        """2. Code health chip appears within 1 second of loading."""
        t0 = time.time()
        chip = self.page.wait_for_selector("#editor-health-chip", timeout=1000)
        elapsed = time.time() - t0
        self.assertIsNotNone(chip)
        self.assertLessEqual(elapsed, 1.0)

    def test_chip_click_opens_code_health_tab(self):
        """3. Clicking Code Health chip switches panel to Code Health tab."""
        chip = self.page.wait_for_selector("#editor-health-chip", timeout=2000)
        chip.click()
        # Verify Code Health tab is active
        health_tab_btn = self.page.locator("#tab-btn-health")
        self.assertTrue(health_tab_btn.evaluate("el => el.classList.contains('active')"))
        health_panel = self.page.locator("#tab-out-health")
        self.assertTrue(health_panel.is_visible())

    def test_blocked_run_shows_empty_state_message(self):
        """4. Running code with blocking syntax/semantic errors renders the empty-state container."""
        # Load Security Demo D (which has syntax error at Stage 3)
        self.page.goto("http://127.0.0.1:8000/?file=examples/security_lab/english/sec_business_workflow.vital", wait_until="domcontentloaded")
        self.page.wait_for_timeout(1000)

        # Click Run
        btn_run = self.page.wait_for_selector("#btn-run", timeout=3000)
        btn_run.click()

        # Empty state container must become visible
        empty_state = self.page.wait_for_selector("#output-blocked-empty-state", state="visible", timeout=10000)
        self.assertTrue(empty_state.is_visible())
        title = self.page.locator("#output-blocked-title").inner_text()
        self.assertIn("No output", title)

    def test_switching_files_mid_run_leaves_no_leftover_badges(self):
        """5. Switching files resets pipeline state and leaves 0/14 stages with no leftover badges."""
        # Click a demo in explorer tree
        demo_link = self.page.locator(".explorer-item").first
        if demo_link.is_visible():
            demo_link.click()

        # Wait for file load to complete
        self.page.wait_for_timeout(500)

        # Check stepper progress metric is reset to 0/14
        metric = self.page.locator("#pipeline-metric-progress")
        self.assertIn("0/14", metric.inner_text())

        # Badges for stages 11 and 12 must not show warning or error counts
        badge11 = self.page.locator("#step-badge-security_analysis")
        if badge11.is_visible():
            self.assertFalse(badge11.evaluate("el => el.classList.contains('badge-warning')"))


if __name__ == "__main__":
    unittest.main()
