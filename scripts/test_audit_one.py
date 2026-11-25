import os
import sys
import time
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, channel="chrome")
    page = browser.new_page(viewport={"width": 1600, "height": 950})
    page.goto("http://127.0.0.1:8000", wait_until="networkidle")

    # Disable AI toggle if on
    toggle_ai = page.query_selector("#toggle-stage12-ai")
    if toggle_ai and page.evaluate("el => el.checked", toggle_ai):
        page.evaluate("el => { el.checked = false; el.dispatchEvent(new Event('change')); }", toggle_ai)

    # Let's test loading hello.vital
    page.evaluate("async () => { await window.__VITAL_IDE__.loadDemoFile('examples/english/hello.vital'); }")
    page.wait_for_timeout(1000)

    t0 = time.time()
    # Click Run
    page.click("#btn-run")

    # Wait for pipeline to finish: state.isExecuting === false or btn-run becomes visible again or status bar
    page.wait_for_function("() => !window.__VITAL_IDE__.state.isExecuting && window.__VITAL_IDE__.state.pipeline.lastCompletedRunId", timeout=15000)
    dur = time.time() - t0
    print(f"Run completed in {dur:.2f}s")

    # Check stage badges
    badges = page.evaluate("""() => {
        const res = {};
        for (let i = 1; i <= 14; i++) {
            const def = window.__VITAL_IDE__.state.pipeline.stages[i - 1];
            const badge = document.getElementById(`step-badge-${def.id}`);
            res[def.id] = badge ? badge.textContent : null;
        }
        return res;
    }""")
    print("Stage badges:", badges)

    # Check preflight strip
    preflight = page.evaluate("""() => {
        const el = document.getElementById("pipeline-preflight-message");
        return el ? el.textContent : null;
    }""")
    print("Preflight strip:", preflight)

    # Check health chip and health panel
    health = page.evaluate("""() => {
        const score = document.getElementById("health-score-number")?.textContent;
        const status = document.getElementById("health-status-text")?.textContent;
        const insec = document.getElementById("health-val-insecure")?.textContent;
        const dead = document.getElementById("health-val-deadcode")?.textContent;
        const density = document.getElementById("health-val-density")?.textContent;
        const btnFix = document.getElementById("btn-health-fix-all")?.textContent;
        return { score, status, insec, dead, density, btnFix };
    }""")
    print("Health:", health)

    browser.close()
