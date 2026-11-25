import os
import sys
import time
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, channel="chrome")
    page = browser.new_page(viewport={"width": 1600, "height": 950})
    page.goto("http://127.0.0.1:8000", wait_until="networkidle")

    # Disable AI toggle
    toggle_ai = page.query_selector("#toggle-stage12-ai")
    if toggle_ai and page.evaluate("el => el.checked", toggle_ai):
        page.evaluate("el => { el.checked = false; el.dispatchEvent(new Event('change')); }", toggle_ai)

    # Test Telugu file
    fpath = 'examples/security_lab/telugu/sec_injection_eval_te.vital'
    page.evaluate(f"async () => {{ await window.__VITAL_IDE__.loadDemoFile('{fpath}', true); }}")
    page.wait_for_timeout(1000)

    # Click Run
    page.click("#btn-run")
    page.wait_for_timeout(500)
    page.wait_for_function("() => !window.__VITAL_IDE__.state.isExecuting", timeout=20000)

    # Close any open drawer and click tab-btn-health
    page.evaluate("""() => {
        const bd = document.getElementById('stage-overlay-backdrop');
        if (bd) bd.style.display = 'none';
        const tb = document.getElementById('tab-btn-health');
        if (tb) tb.click();
    }""")
    page.wait_for_timeout(500)

    # Trigger click on Fix All button
    page.evaluate("() => document.getElementById('btn-health-fix-all').click()")
    print("Clicked Fix All, waiting for modal...")

    page.wait_for_selector("#fix-modal-overlay[style*='display: flex']", timeout=30000)
    page.wait_for_timeout(1000)

    modal_info = page.evaluate("""() => {
        const title = document.getElementById("fix-modal-title")?.textContent?.trim();
        const rows = document.querySelectorAll(".fix-error-card")?.length;
        const btnLabel = document.getElementById("btn-apply-fix")?.textContent?.trim();
        const valBadge = document.getElementById("fix-modal-validation")?.textContent?.trim();
        return { title, rows, btnLabel, valBadge };
    }""")
    print("Modal Info:", modal_info)

    # Close modal
    page.click("#btn-close-fix-modal")
    page.wait_for_timeout(300)

    browser.close()
