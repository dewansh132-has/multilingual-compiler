# -*- coding: utf-8 -*-
"""
scripts/capture_report_screenshots.py — Capture exact required screenshots for VITAL documentation report.
Viewport: 1600x1000, 100% zoom. Target dir: docs/report_assets/screenshots/captured/
"""

import os
import sys
import time
from playwright.sync_api import sync_playwright

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "report_assets", "screenshots", "captured")
os.makedirs(OUT_DIR, exist_ok=True)

BASE_URL = "http://127.0.0.1:8000"

def wait_for_pipeline_finish(page, timeout=10000):
    page.wait_for_timeout(3000)
    try:
        page.wait_for_function(
            "() => window.__VITAL_IDE__ && !window.__VITAL_IDE__.state.isExecuting",
            timeout=timeout
        )
    except Exception as e:
        print(f"Wait note: {e}")
    page.wait_for_timeout(1500)

def switch_tab(page, tab_id):
    page.evaluate(f"""() => {{
        const btn = document.querySelector(`[data-tab="{tab_id}"]`);
        if (btn) btn.click();
    }}""")
    page.wait_for_timeout(600)

def open_stage_drawer(page, stage_id):
    page.evaluate(f"""() => {{
        const el = document.querySelector(`[data-stage-id="{stage_id}"], [data-stage="{stage_id}"]`);
        if (el) el.click();
    }}""")
    page.wait_for_timeout(1000)

def main():
    print(f"Launching Playwright to capture remaining screenshots into: {OUT_DIR}")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1600, "height": 1000}, device_scale_factor=1.0)
        page = context.new_page()

        # 7. Demo A stopped at Stage 5 (sec_auth_access_scope_te.vital)
        print("[7] Demo A stopped at Stage 5...")
        page.goto(f"{BASE_URL}/?file=examples/security_lab/telugu/sec_auth_access_scope_te.vital")
        page.wait_for_timeout(2000)
        page.evaluate("""() => {
            const cb = document.getElementById('toggle-stage12-ai');
            if (cb && cb.checked) { cb.checked = false; cb.dispatchEvent(new Event('change')); }
        }""")
        page.click("#btn-run")
        wait_for_pipeline_finish(page)
        switch_tab(page, "tab-out-program")
        page.screenshot(path=os.path.join(OUT_DIR, "demo_a_stopped_stage5.png"))

        # 8. Demo D stopped at Stage 3 (sec_business_workflow_logic_te.vital)
        print("[8] Demo D stopped at Stage 3...")
        page.goto(f"{BASE_URL}/?file=examples/security_lab/telugu/sec_business_workflow_logic_te.vital")
        page.wait_for_timeout(2000)
        page.evaluate("""() => {
            const cb = document.getElementById('toggle-stage12-ai');
            if (cb && cb.checked) { cb.checked = false; cb.dispatchEvent(new Event('change')); }
        }""")
        page.click("#btn-run")
        wait_for_pipeline_finish(page)
        switch_tab(page, "tab-out-program")
        page.screenshot(path=os.path.join(OUT_DIR, "demo_d_stopped_stage3.png"))

        # 9. Demo B stopped at Stage 11 (sec_data_concurrency_race_te.vital)
        print("[9] Demo B stopped at Stage 11...")
        page.goto(f"{BASE_URL}/?file=examples/security_lab/telugu/sec_data_concurrency_race_te.vital")
        page.wait_for_timeout(2000)
        page.evaluate("""() => {
            const cb = document.getElementById('toggle-stage12-ai');
            if (cb && cb.checked) { cb.checked = false; cb.dispatchEvent(new Event('change')); }
        }""")
        page.click("#btn-run")
        wait_for_pipeline_finish(page)
        switch_tab(page, "tab-out-program")
        page.screenshot(path=os.path.join(OUT_DIR, "demo_b_stopped_stage11.png"))

        # 10. Demo C stopped at Stage 11 (sec_injection_eval_te.vital)
        print("[10] Demo C stopped at Stage 11...")
        page.goto(f"{BASE_URL}/?file=examples/security_lab/telugu/sec_injection_eval_te.vital")
        page.wait_for_timeout(2000)
        page.evaluate("""() => {
            const cb = document.getElementById('toggle-stage12-ai');
            if (cb && cb.checked) { cb.checked = false; cb.dispatchEvent(new Event('change')); }
        }""")
        page.click("#btn-run")
        wait_for_pipeline_finish(page)
        switch_tab(page, "tab-out-program")
        page.screenshot(path=os.path.join(OUT_DIR, "demo_c_stopped_stage11.png"))

        # 11. Stage 12 drawer
        print("[11] Capturing Stage 12 drawer...")
        open_stage_drawer(page, "stage_12_ai_security")
        page.screenshot(path=os.path.join(OUT_DIR, "stage12_drawer.png"))

        browser.close()
        print("All remaining screenshots successfully captured!")

if __name__ == "__main__":
    main()
