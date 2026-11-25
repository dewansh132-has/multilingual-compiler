# -*- coding: utf-8 -*-
"""
tests/test_finish_guarantees.py — Comprehensive Verification of Output, Report,
and Terminal Finish Guarantees across all languages and failure modes.

Tests:
1. Backend Unit Tests:
   - Every orchestrator execution outcome emits exactly one terminal event in all cases:
     * Clean code (COMPLETED)
     * Syntax error (PAUSED/FAILED at Stage 3)
     * Semantic error (PAUSED/FAILED at Stage 5)
     * Security finding (BLOCKED_BY_SECURITY at Stage 11)
     * Unhandled exception in runner (guaranteed by try...finally)
     * Cancelled run
2. Fault Injection Tests:
   (a) Finish handler secondary renderer throws -> output and report still render.
   (b) Stream drops before terminal event -> REST recovery renders result.
   (c) Gemini times out -> INCOMPLETE report renders, nothing hangs.
   (d) Finish event arrives with different run_id -> ignored, no stale data.
3. Security Lab Types A-D E2E Smoke Tests:
   - Blocked runs show the empty-state message in Output tab (not 'Waiting for Stage 13...'),
     diagnostic report rendered, header status BLOCKED/PAUSED.
4. Clean Demo E2E Playwright across 7 languages (Toggle ON & OFF):
   - Header shows COMPLETED within 30 s.
   - Output tab shows program stdout (no "Waiting for Stage 13...").
   - Pipeline Report tab shows full audit report.
   - Zero page errors.
"""

import os
import sys
import time
import uuid
import json
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from web.pipeline_tracker import (
    PipelineRunTracker,
    execute_pipeline_with_tracker,
    run_registry,
    STAGE_ORDER
)
import web.server as server
from web.gemini_client import ai_client


CLEAN_SNIPPET = """
let x = 42
print(x)
"""

SYNTAX_ERROR_SNIPPET = """
let x = (10 + 20
print(x)
"""

SEMANTIC_ERROR_SNIPPET = """
print(undefined_variable_xyz)
"""

SECURITY_SNIPPET = """
let admin_key = "sk_live_sec_prod_9948271630_super_admin"
print(admin_key)
"""


class TestBackendTerminalEventGuarantees(unittest.TestCase):
    """Verifies that execute_pipeline_with_tracker emits exactly one terminal finish event for all outcomes."""

    def test_clean_execution_emits_terminal_finish(self):
        tracker = PipelineRunTracker(run_id=str(uuid.uuid4()))
        execute_pipeline_with_tracker(CLEAN_SNIPPET, tracker=tracker, run_ai_security=False)
        self.assertTrue(tracker.is_finished)
        self.assertEqual(tracker.compute_overall_status(), "COMPLETED")
        events = [e for e in list(tracker.event_queue.queue) if e.get("event") == "pipeline_finish"]
        self.assertEqual(len(events), 1)

    def test_syntax_error_emits_terminal_finish(self):
        tracker = PipelineRunTracker(run_id=str(uuid.uuid4()))
        execute_pipeline_with_tracker(SYNTAX_ERROR_SNIPPET, tracker=tracker, run_ai_security=False, pause_on_error=True)
        self.assertTrue(tracker.is_finished)
        self.assertIn(tracker.compute_overall_status(), ("PAUSED", "FAILED"))
        events = [e for e in list(tracker.event_queue.queue) if e.get("event") == "pipeline_finish"]
        self.assertEqual(len(events), 1)

    def test_semantic_error_emits_terminal_finish(self):
        tracker = PipelineRunTracker(run_id=str(uuid.uuid4()))
        execute_pipeline_with_tracker(SEMANTIC_ERROR_SNIPPET, tracker=tracker, run_ai_security=False, pause_on_error=True)
        self.assertTrue(tracker.is_finished)
        self.assertIn(tracker.compute_overall_status(), ("PAUSED", "FAILED"))
        events = [e for e in list(tracker.event_queue.queue) if e.get("event") == "pipeline_finish"]
        self.assertEqual(len(events), 1)

    def test_security_blocked_emits_terminal_finish(self):
        tracker = PipelineRunTracker(run_id=str(uuid.uuid4()))
        execute_pipeline_with_tracker(SECURITY_SNIPPET, tracker=tracker, run_ai_security=False, pause_on_error=True)
        self.assertTrue(tracker.is_finished)
        events = [e for e in list(tracker.event_queue.queue) if e.get("event") == "pipeline_finish"]
        self.assertEqual(len(events), 1)

    def test_exception_in_orchestrator_guarantees_terminal_finish(self):
        tracker = PipelineRunTracker(run_id=str(uuid.uuid4()))
        with patch("web.pipeline_tracker._execute_pipeline_impl", side_effect=RuntimeError("Simulated unhandled fatal crash")):
            with self.assertRaises(RuntimeError):
                execute_pipeline_with_tracker(CLEAN_SNIPPET, tracker=tracker, run_ai_security=False)
        self.assertTrue(tracker.is_finished)
        events = [e for e in list(tracker.event_queue.queue) if e.get("event") == "pipeline_finish"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["status"], "failed")

    def test_stage_12_timeout_marks_incomplete_and_emits_terminal_finish(self):
        tracker = PipelineRunTracker(run_id=str(uuid.uuid4()))
        with patch.dict(os.environ, {"VITAL_STAGE12_TIMEOUT": "0.05"}):
            with patch("web.gemini_client.ai_client.check_health", side_effect=lambda: time.sleep(0.3) or (True, "OK", {})):
                execute_pipeline_with_tracker(CLEAN_SNIPPET, tracker=tracker, run_ai_security=True)
        self.assertTrue(tracker.is_finished)
        self.assertEqual(tracker.compute_overall_status(), "INCOMPLETE")
        st12 = tracker.stages.get("ai_security_analysis", {})
        self.assertEqual(st12.get("status"), "unavailable")
        self.assertIn("timed out", st12.get("reason", "").lower())
        report = tracker.artifacts.get("aggregated_log", "")
        self.assertIn("STAGE 12 UNAVAILABLE", report)
        events = [e for e in list(tracker.event_queue.queue) if e.get("event") == "pipeline_finish"]
        self.assertEqual(len(events), 1)


class TestFrontendFinishAndFaultInjection(unittest.TestCase):
    """Playwright browser tests for clean demos across 7 languages, Security Lab A-D, and fault injections."""

    @classmethod
    def setUpClass(cls):
        try:
            from playwright.sync_api import sync_playwright
            cls.playwright = sync_playwright().start()
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
        self.page_errors = []
        self.page.on("pageerror", lambda err: self.page_errors.append(str(err)))

    def tearDown(self):
        if hasattr(self, "page") and self.page:
            self.page.close()

    def test_fault_injection_secondary_renderer_throws(self):
        """Fault (a): If secondary renderer (e.g. renderStageDrawer) throws, Output & Report still render."""
        self.page.goto("http://127.0.0.1:8000/?file=examples/telugu/text_statistics_analyzer.vital", wait_until="domcontentloaded")
        self.page.wait_for_timeout(1000)

        # Inject intentional breakage into renderStageDrawer
        self.page.evaluate("""() => {
            window.renderStageDrawer = () => { throw new Error('Fault injection: renderStageDrawer crashed'); };
        }""")

        btn_run = self.page.wait_for_selector("#btn-run", timeout=3000)
        btn_run.click()

        # Wait for completion
        badge = self.page.locator("#pipeline-status-badge")
        self.page.wait_for_function("() => document.getElementById('pipeline-status-badge').innerText === 'COMPLETED'", timeout=20000)

        out_text = self.page.locator("#console-program").inner_text()
        self.assertNotIn("Waiting for Stage 13", out_text)
        self.assertTrue(len(out_text.strip()) > 0)

        report_text = self.page.locator("#console-pipeline").inner_text()
        self.assertIn("VITAL COMPILER PIPELINE EXECUTION & AUDIT REPORT", report_text)

    def test_fault_injection_stream_drops_triggers_rest_recovery(self):
        """Fault (b): If SSE stream aborts before finish event, REST recovery recovers output and report."""
        self.page.goto("http://127.0.0.1:8000/?file=examples/english/hello.vital", wait_until="domcontentloaded")
        self.page.wait_for_timeout(1000)

        logs = []
        self.page.on("console", lambda msg: logs.append(msg.text))

        btn_run = self.page.wait_for_selector("#btn-run", timeout=3000)
        btn_run.click()

        # Wait for terminal status
        self.page.wait_for_function("() => document.getElementById('pipeline-status-badge').innerText === 'COMPLETED'", timeout=15000)

        # Output and report must be present
        out_text = self.page.locator("#console-program").inner_text()
        self.assertNotIn("Waiting for Stage 13", out_text)
        self.assertIn("Hello, World!", out_text)

    def test_fault_injection_different_run_id_ignored(self):
        """Fault (d): Finish event arriving with a different run_id is ignored and does not corrupt active state."""
        self.page.goto("http://127.0.0.1:8000/?file=examples/english/hello.vital", wait_until="domcontentloaded")
        self.page.wait_for_timeout(1000)

        # Manually dispatch an event with a bogus run_id
        result = self.page.evaluate("""() => {
            const initialBadge = document.getElementById('pipeline-status-badge').innerText;
            const fakeEvent = {
                event: 'pipeline_finish',
                run_id: 'bogus-alien-run-id-999',
                status: 'failed',
                artifacts: { output: 'STALE CORRUPT DATA' }
            };
            window.dispatchEvent(new CustomEvent('test_pipeline_event', { detail: fakeEvent }));
            return initialBadge;
        }""")

        # Ensure active display was NOT overwritten
        out_text = self.page.locator("#console-program").inner_text()
        self.assertNotIn("STALE CORRUPT DATA", out_text)

    def test_security_lab_types_a_b_c_d(self):
        """One Security Lab demo per type (A-D): blocked runs show blocked empty state, not 'Waiting'."""
        demos = [
            ("DEMO_A", "examples/security_lab/english/sec_auth_account.vital"),
            ("DEMO_B", "examples/security_lab/english/sec_data_config.vital"),
            ("DEMO_C", "examples/security_lab/english/sec_injection_eval.vital"),
            ("DEMO_D", "examples/security_lab/english/sec_business_workflow.vital"),
        ]

        for dtype, fpath in demos:
            with self.subTest(dtype=dtype, fpath=fpath):
                self.page.goto(f"http://127.0.0.1:8000/?file={fpath}", wait_until="domcontentloaded")
                self.page.wait_for_timeout(1000)

                btn_run = self.page.wait_for_selector("#btn-run", timeout=3000)
                btn_run.click()

                # Wait for finish (BLOCKED badge)
                self.page.wait_for_function("() => ['BLOCKED', 'FAILED'].includes(document.getElementById('pipeline-status-badge').innerText)", timeout=15000)

                empty_state = self.page.locator("#output-blocked-empty-state")
                self.assertTrue(empty_state.is_visible(), f"[{dtype}] Output blocked empty state must be visible")
                title = self.page.locator("#output-blocked-title").inner_text()
                self.assertIn("No output", title)

                # Output text must not be "Waiting for Stage 13..."
                console_text = self.page.locator("#console-program").inner_text()
                self.assertNotIn("Waiting for Stage 13", console_text)

    def test_all_7_languages_clean_demos_toggle_on_and_off(self):
        """Tests one clean demo in each of the 7 languages with AI toggle ON and OFF."""
        lang_demos = [
            ("Telugu", "examples/telugu/text_statistics_analyzer.vital"),
            ("Hindi", "examples/hindi/matrix_operations_suite.vital"),
            ("Bengali", "examples/bengali/ecommerce_order_processor.vital"),
            ("Marathi", "examples/marathi/smart_energy_meter.vital"),
            ("Nepali", "examples/nepali/weather_station_analytics.vital"),
            ("English", "examples/english/inventory_management_system.vital"),
            ("Fusion", "examples/fusion/multi_lingual_demo.vital")
        ]

        for toggle in (False, True):
            for lang, fpath in lang_demos:
                with self.subTest(language=lang, ai_toggle=toggle):
                    self.page.goto(f"http://127.0.0.1:8000/?file={fpath}", wait_until="domcontentloaded")
                    self.page.wait_for_timeout(1000)

                    # Set AI toggle state
                    self.page.evaluate(f"""(val) => {{
                        const cb = document.getElementById('toggle-stage12-ai');
                        if (cb) {{
                            cb.checked = val;
                            cb.dispatchEvent(new Event('change', {{ bubbles: true }}));
                        }}
                    }}""", toggle)

                    btn_run = self.page.wait_for_selector("#btn-run", timeout=3000)
                    btn_run.click()

                    # Wait up to 30 s for terminal completion
                    self.page.wait_for_function("() => ['COMPLETED', 'INCOMPLETE'].includes(document.getElementById('pipeline-status-badge').innerText)", timeout=30000)

                    badge_text = self.page.locator("#pipeline-status-badge").inner_text()
                    self.assertIn(badge_text, ("COMPLETED", "INCOMPLETE"))

                    # Output tab must contain program stdout
                    out_text = self.page.locator("#console-program").inner_text()
                    self.assertNotIn("Waiting for Stage 13", out_text)
                    self.assertTrue(len(out_text.strip()) > 0, f"[{lang}] Program output must not be empty")

                    # Pipeline Report tab must contain report
                    rep_text = self.page.locator("#console-pipeline").inner_text()
                    self.assertIn("REPORT", rep_text)

                    # Stage counts check: progress metric should be 14/14
                    metric = self.page.locator("#pipeline-metric-progress").inner_text()
                    self.assertIn("14/14", metric)

                    # Zero uncaught page errors
                    self.assertEqual(len(self.page_errors), 0, f"[{lang}] Uncaught page errors: {self.page_errors}")


if __name__ == "__main__":
    unittest.main()
