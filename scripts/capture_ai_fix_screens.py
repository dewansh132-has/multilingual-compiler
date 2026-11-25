# -*- coding: utf-8 -*-
"""
scripts/capture_ai_fix_screens.py — Capture UI Evidence for Multi-Stage AI Fix & Re-run

Captures:
1. Stage drawer showing "Fix with AI (N)" button on a stage with diagnostics.
2. AI Fix & Re-run summary dialog showing iteration logs, whole buffer diff, and Undo button.
"""

import os
import sys
import time
from playwright.sync_api import sync_playwright

def main():
    os.makedirs("reports", exist_ok=True)
    drawer_png = os.path.abspath("reports/ai_fix_stage_drawer.png")
    summary_png = os.path.abspath("reports/ai_fix_summary_modal.png")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()

        print("Navigating to VITAL IDE with Telugu Demo D...")
        target_url = "http://127.0.0.1:8000/?file=examples/security_lab/telugu/sec_business_workflow_te.vital"
        page.goto(target_url, wait_until="networkidle")
        page.wait_for_timeout(3000)

        # Press Run to execute pipeline
        print("Pressing Run button...")
        run_btn = page.locator("#btn-run")
        run_btn.click()

        # Wait for pipeline to halt at failed Stage 3 and auto-open stage drawer
        print("Waiting for Stage 3 drawer to open...")
        page.wait_for_selector("#stage-overlay-backdrop:not([style*='display: none'])", timeout=20000)
        page.wait_for_timeout(1500)

        # Capture drawer screenshot showing "Fix with AI (N)" button
        print(f"Capturing stage drawer screenshot -> {drawer_png}")
        page.screenshot(path=drawer_png)

        # Close the drawer
        print("Closing stage drawer...")
        close_btn = page.locator("#drawer-close-btn")
        if close_btn.count() > 0:
            close_btn.click()
            page.wait_for_timeout(1000)

        # Wait for "AI Fix & Re-run" button in header
        print("Checking 'AI Fix & Re-run' button in header...")
        page.wait_for_selector("#btn-pipeline-ai-fix-rerun:not([style*='display: none'])", timeout=10000)
        fix_rerun_btn = page.locator("#btn-pipeline-ai-fix-rerun")
        fix_rerun_btn.click()

        # Wait for AI Fix & Re-run summary modal to appear and complete
        print("Waiting for summary modal...")
        page.wait_for_selector("#ai-fix-rerun-modal-overlay:not([style*='display: none'])", timeout=30000)
        page.wait_for_selector("#ai-fix-rerun-summary-section:not([style*='display: none'])", timeout=45000)
        page.wait_for_timeout(2000)

        # Capture modal screenshot
        print(f"Capturing summary modal screenshot -> {summary_png}")
        page.screenshot(path=summary_png)

        browser.close()
        print("Screenshots captured successfully.")

if __name__ == "__main__":
    main()
