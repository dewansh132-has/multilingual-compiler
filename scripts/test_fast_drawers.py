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

    # Extract all 14 stage drawer stats by clicking each node in DOM
    t0 = time.time()
    drawer_results = page.evaluate("""() => {
        const res = {};
        const stages = window.__VITAL_IDE__.state.pipeline.stages || [];
        for (const st of stages) {
            const node = document.getElementById(`step-node-${st.id}`);
            if (node) node.click();
            let findingsMetric = null;
            document.querySelectorAll(".drawer-stat-card").forEach(c => {
                const lbl = c.querySelector(".drawer-stat-label");
                if (lbl && lbl.textContent.includes("Findings / Warnings")) {
                    findingsMetric = c.querySelector(".drawer-stat-value")?.textContent?.trim();
                }
            });
            const pill = document.querySelector(".stage-findings-count-badge")?.textContent?.trim() || "";
            const cardsCount = document.querySelectorAll(".stage-finding-card")?.length || 0;
            const statusPill = document.querySelector(".drawer-status-pill")?.textContent?.trim() || "";
            res[st.id] = { findingsMetric, pill, cardsCount, statusPill };
        }
        const closeBtn = document.getElementById("btn-close-drawer");
        if (closeBtn) closeBtn.click();
        const bd = document.getElementById("stage-overlay-backdrop");
        if (bd) bd.style.display = "none";
        return res;
    }""")
    dur = time.time() - t0
    print(f"Extracted all 14 stage drawers in {dur*1000:.1f}ms!")
    for s_id, s_data in drawer_results.items():
        print(f"  {s_id:22s}: metric={s_data['findingsMetric']} pill='{s_data['pill']}' cards={s_data['cardsCount']} headerStatus='{s_data['statusPill']}'")

    browser.close()
