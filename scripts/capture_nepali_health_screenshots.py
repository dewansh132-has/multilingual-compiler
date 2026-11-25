import os
import sys
import time
from playwright.sync_api import sync_playwright

os.makedirs("docs/screenshots", exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, channel="msedge")
    page = browser.new_page(viewport={"width": 1400, "height": 900})

    print("Navigating to Web IDE with Nepali demo...")
    page.goto("http://localhost:8000/?file=examples/nepali/weather_station_analytics.vital", wait_until="networkidle")
    time.sleep(3)

    # Populate editor with unsuppressed code to show dead code (11.5%)
    print("Unsuppressing dead code in editor...")
    page.evaluate("""() => {
        let code = window.__VITAL_IDE__.state.editor.getValue();
        code = code.replace('यदि (सामान्य_वायुमण्डलीय_चाप > 0) {\\n    छाप("हिमाली जलवायु तथा मौसम अनुगमन प्रणाली सुरु:")\\n}\\n', '');
        code = code.replace('    यदि (औसत_तातो + विन्डचिल > -99999) {\\n        मान _मौसम_मान्य = 1\\n    }\\n', '');
        code = code.replace('यदि (तुसारो_1 + तुसारो_2 + अक्सिजन_5000 + अक्सिजन_2500 + यूभी_1 + यूभी_2 + ताल_विस्फोट + आर्द्रता_1 + आर्द्रता_2 + नदी_चेतावनी_1 + नदी_चेतावनी_2 + वायु_गुणस्तर_1 + वायु_गुणस्तर_2 + पग्लिने_दर + बुलेटिन_1 + बुलेटिन_2 > -99999) {\\n    मान _मौसम_अहवाल = 1\\n}\\n', '');
        window.__VITAL_IDE__.state.editor.setValue(code);
        window.__VITAL_IDE__.runHealthAnalysis(true);
    }""")
    time.sleep(3)

    # Switch to Health tab
    print("Switching to Health tab...")
    page.evaluate("""() => {
        const tab = document.getElementById('tab-btn-health');
        if (tab) tab.click();
    }""")
    time.sleep(2)

    # Open Fix All Modal to show Before fix modal dialog
    print("Clicking Fix All Issues button to open dialog...")
    page.evaluate("""() => {
        const btn = document.getElementById('btn-health-fix-all');
        if (btn) btn.click();
    }""")
    time.sleep(4)

    # Capture before screenshot (modal open showing honest badges, deterministic label, per-error hunks)
    page.screenshot(path="docs/screenshots/code_health_nepali_before.png")
    print("Saved docs/screenshots/code_health_nepali_before.png")

    # Click Apply Fix button
    print("Applying fixes...")
    page.evaluate("""() => {
        const applyBtn = document.getElementById('btn-apply-fix');
        if (applyBtn) applyBtn.click();
    }""")
    time.sleep(3)

    # Run the compiler pipeline to show COMPLETED green progress bar
    print("Running compiler on repaired code...")
    page.evaluate("""() => {
        const runBtn = document.getElementById('btn-run');
        if (runBtn) runBtn.click();
    }""")
    time.sleep(5)

    # Switch back to Health tab to see Healthy status, 100 score, 0% dead code, and real Fix Delta box
    print("Refreshing health analysis tab...")
    page.evaluate("""() => {
        const tab = document.getElementById('tab-btn-health');
        if (tab) tab.click();
        window.__VITAL_IDE__.runHealthAnalysis(true);
    }""")
    time.sleep(3)

    # Capture after screenshot
    page.screenshot(path="docs/screenshots/code_health_nepali_after.png")
    print("Saved docs/screenshots/code_health_nepali_after.png")

    browser.close()
    print("Playwright screenshots completed successfully.")
