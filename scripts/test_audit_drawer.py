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

    # Test Telugu file
    fpath = 'examples/security_lab/telugu/sec_injection_eval_te.vital'
    page.evaluate(f"async () => {{ await window.__VITAL_IDE__.loadDemoFile('{fpath}', true); }}")
    page.wait_for_timeout(1000)

    # Click Run
    page.click("#btn-run")
    # Wait until isExecuting becomes true then false, or wait until isExecuting is false
    page.wait_for_timeout(500)
    page.wait_for_function("() => !window.__VITAL_IDE__.state.isExecuting", timeout=20000)
    print("Run completed! Status:", page.evaluate("() => window.__VITAL_IDE__.state.pipeline.finishStatus"))

    # Stage badges
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

    # Open stage 11 drawer
    page.evaluate("() => { const n = document.getElementById('step-node-security_analysis'); if (n) n.click(); }")
    page.wait_for_timeout(500)

    # Read drawer stats
    drawer_stats = page.evaluate("""() => {
        let findingsMetric = null;
        document.querySelectorAll(".drawer-stat-card").forEach(c => {
            const lbl = c.querySelector(".drawer-stat-label");
            if (lbl && lbl.textContent.includes("Findings / Warnings")) {
                findingsMetric = c.querySelector(".drawer-stat-value")?.textContent?.trim();
            }
        });
        const pill = document.querySelector(".stage-findings-count-badge")?.textContent?.trim();
        const cardsCount = document.querySelectorAll(".stage-finding-card")?.length;
        return { findingsMetric, pill, cardsCount };
    }""")
    print("Stage 11 drawer stats:", drawer_stats)

    # Close drawer
    page.evaluate("() => { if (typeof closeStageDrawer === 'function') closeStageDrawer(); }")
    page.wait_for_timeout(300)

    # Check Fix All button in Health panel
    btn_fix_all = page.evaluate("() => document.getElementById('btn-health-fix-all')?.textContent?.trim()")
    print("btn-health-fix-all:", btn_fix_all)

    browser.close()
