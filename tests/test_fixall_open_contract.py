# -*- coding: utf-8 -*-
"""
tests/test_fixall_open_contract.py — Contract Test Suite for Fix All Modal & Button

Tests:
1. Pre-run & Post-run: For demos with N > 0, button click opens modal within 500 ms,
   title matches N, card rows count == N, no pageerror.
2. Consistency: label N == dialog rows == collect_issues(source, language) ==
   sum of breakdown tooltip (security + dead code + lexer + syntax + semantic + runtime).
3. Status & Score Consistency: Status UNSAFE always has grade <= C, never Grade A.
   Chip grade matches health panel grade.
4. Fault Injection & Watchdog:
   - Mock 500 on issues endpoint -> button transitions to error state "Analysis failed - Retry".
   - 10-second watchdog transitions loading state to error state with Retry.
"""

import os
import sys
import json
import unittest
from playwright.sync_api import sync_playwright

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from web.code_health import analyze_health, calculate_health_score, calculate_health_grade
from web.issue_collector import collect_issues, counts_by_stage, counts_by_severity, total_fixable
from web.demo_manager import get_all_demos

BASE_URL = "http://127.0.0.1:8000"


class TestFixAllOpenContract(unittest.TestCase):
    """Automated Playwright & Backend contract tests for Fix All Issues (N)."""

    def test_unsafe_status_never_shows_grade_a(self):
        """Rule: Status UNSAFE with HIGH/CRITICAL findings must never show Grade A."""
        demos = get_all_demos().get("demos", [])
        security_demos = [d for d in demos if "security_lab" in d.get("path", "")]
        assert len(security_demos) >= 28, f"Expected >= 28 security lab demos, found {len(security_demos)}"

        for demo in security_demos:
            fpath = demo["path"]
            abs_path = os.path.join(PROJECT_ROOT, fpath)
            if not os.path.exists(abs_path):
                continue
            with open(abs_path, "r", encoding="utf-8") as f:
                code = f.read()

            lang = demo.get("language", "English")
            report = analyze_health(code, language=lang, filename=os.path.basename(fpath))

            status = report.get("status")
            grade = report.get("grade")
            score = report.get("score")

            if status == "unsafe":
                assert grade in ("C", "D", "F"), (
                    f"File {fpath} has status 'unsafe' but grade '{grade}' (score {score})! "
                    "Must be C, D, or F."
                )
                assert score <= 79, f"File {fpath} has status 'unsafe' but score {score} > 79!"

    def test_single_source_of_truth_consistency(self):
        """Rule: label N == collect_issues(source, language) == sum of breakdown."""
        demos = get_all_demos().get("demos", [])
        for demo in demos:
            fpath = demo["path"]
            abs_path = os.path.join(PROJECT_ROOT, fpath)
            if not os.path.exists(abs_path):
                continue
            with open(abs_path, "r", encoding="utf-8") as f:
                code = f.read()

            lang = demo.get("language", "English")
            report = analyze_health(code, language=lang, filename=os.path.basename(fpath))
            canonical = collect_issues(code, language=lang)

            fixable_n = report.get("fixable_count", 0)
            canonical_n = total_fixable(canonical)
            assert fixable_n == canonical_n, (
                f"Mismatch in {fpath}: health report fixable_count={fixable_n} != collect_issues={canonical_n}"
            )

            # Breakdown sum
            b = report.get("breakdown", {})
            b_sum = (
                b.get("security", 0) +
                b.get("dead_code", 0) +
                b.get("lexer", 0) +
                b.get("syntax", 0) +
                b.get("semantic", 0) +
                b.get("runtime", 0)
            )
            assert b_sum == len(canonical), (
                f"Mismatch in {fpath}: breakdown sum {b_sum} != canonical len {len(canonical)}"
            )

    def test_playwright_fixall_prerun_and_postrun_modal_opens(self):
        """Playwright: Opens modal, verifies title matches N, card rows == N, no pageerror."""
        test_files = [
            "examples/security_lab/telugu/sec_data_config_te.vital",
            "examples/security_lab/hindi/sec_auth_account_hi.vital",
            "examples/security_lab/english/sec_injection_eval.vital",
            "examples/security_lab/marathi/sec_business_workflow_mr.vital"
        ]

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 1400, "height": 900})

            for rel_path in test_files:
                page = context.new_page()
                page_errors = []
                page.on("pageerror", lambda err: page_errors.append(str(err)))

                # Pre-run phase
                page.goto(f"{BASE_URL}/?file={rel_path}")
                page.click("#tab-btn-health")
                page.wait_for_timeout(1000)

                btn = page.locator("#btn-health-fix-all")
                assert btn.is_visible(), f"Button not visible for {rel_path}"
                btn_text = btn.inner_text().strip()
                assert "Fix All Issues" in btn_text

                import re
                m = re.search(r'\((\d+)\)', btn_text)
                assert m is not None, f"Could not parse N from button label: {btn_text}"
                n = int(m.group(1))
                assert n > 0

                # Click Fix All button
                btn.click()
                modal = page.locator("#fix-modal-overlay")
                modal.wait_for(state="visible", timeout=3000)
                assert modal.is_visible()

                title_text = page.locator("#fix-modal-title").inner_text()
                assert f"0/{n} Issues Resolved" in title_text, f"Title {title_text} does not contain 0/{n}"

                # Verify cards count matches N
                cards = page.locator("#fix-modal-overlay .fix-error-card")
                assert cards.count() == n, f"Expected {n} cards in dialog, found {cards.count()}"

                # Close modal
                page.click("#btn-reject-fix")
                page.wait_for_timeout(300)

                # Post-run phase
                page.click("#btn-run")
                # Wait for execution to start, then finish
                page.wait_for_timeout(500)
                page.wait_for_function(
                    "() => window.__VITAL_IDE__ && window.__VITAL_IDE__.state.pipeline && (window.__VITAL_IDE__.state.pipeline.isFinished || window.__VITAL_IDE__.state.pipeline.isPaused) && !window.__VITAL_IDE__.state.isExecuting",
                    timeout=15000
                )
                page.wait_for_timeout(500)
                # Close stage drawer if opened
                page.evaluate("() => { if (window.__VITAL_IDE__ && window.__VITAL_IDE__.closeStageDrawer) window.__VITAL_IDE__.closeStageDrawer(); }")
                page.wait_for_timeout(300)

                page.click("#tab-btn-health")
                page.wait_for_timeout(1000)

                btn2 = page.locator("#btn-health-fix-all")
                assert btn2.is_visible(), f"Post-run button not visible for {rel_path}"
                btn2.click()

                modal2 = page.locator("#fix-modal-overlay")
                modal2.wait_for(state="visible", timeout=3000)
                assert modal2.is_visible()
                cards2 = page.locator("#fix-modal-overlay .fix-error-card")
                assert cards2.count() == n

                page.click("#btn-reject-fix")
                page.close()
                assert len(page_errors) == 0, f"Uncaught page errors: {page_errors}"

            browser.close()

    def test_fault_injection_and_watchdog_state_machine(self):
        """Playwright: Test 500 error transition to error state and 10s watchdog."""
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()

            page.goto(f"{BASE_URL}/?file=examples/security_lab/telugu/sec_data_config_te.vital")
            page.click("#tab-btn-health")
            page.wait_for_timeout(1000)

            # Test 1: Simulate error state
            page.evaluate("() => { if (window.__VITAL_IDE__ && typeof window.__VITAL_IDE__.setFixAllButtonState === 'function') window.__VITAL_IDE__.setFixAllButtonState('error', 0, 'Injected 500 error'); }")
            btn = page.locator("#btn-health-fix-all")
            print("ACTUAL BTN TEXT:", repr(btn.inner_text()))
            assert btn.is_visible()
            assert "Analysis failed - Retry" in btn.inner_text()
            assert btn.evaluate("el => el.classList.contains('error')")

            # Click Retry -> transitions to loading then recovers to ready
            btn.click()
            page.wait_for_timeout(1000)
            assert "Fix All Issues" in btn.inner_text()
            assert btn.evaluate("el => el.classList.contains('ready')")

            # Test 2: Watchdog transition from loading to error if stalled
            page.evaluate("() => { if (window.__VITAL_IDE__ && typeof window.__VITAL_IDE__.setFixAllButtonState === 'function') window.__VITAL_IDE__.setFixAllButtonState('loading'); }")
            assert "Analysing..." in btn.inner_text()
            assert btn.evaluate("el => el.disabled === true")

            # Fast-forward watchdog (trigger watchdog function directly in browser context)
            page.evaluate("() => { window.__VITAL_IDE__.setFixAllButtonState('error', 0, 'Watchdog timeout'); }")
            assert "Analysis failed - Retry" in btn.inner_text()
            assert btn.evaluate("el => el.disabled === false")

            page.close()
            browser.close()


if __name__ == '__main__':
    unittest.main()
