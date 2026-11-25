import os
import sys
import time
from playwright.sync_api import sync_playwright

FILES = [
    {
        "key": "hello_en",
        "name": "hello.vital (English)",
        "path": "examples/english/hello.vital",
        "expected_stop": 14,
        "expected_status": "COMPLETED",
        "has_output": True
    },
    {
        "key": "sec_auth_fusion",
        "name": "sec_auth_account_fusion.vital",
        "path": "examples/security_lab/fusion/sec_auth_account_fusion.vital",
        "expected_stop": 5,
        "expected_status": "FAILED",
        "has_output": False
    },
    {
        "key": "sec_business_te",
        "name": "sec_business_workflow_te.vital",
        "path": "examples/security_lab/telugu/sec_business_workflow_te.vital",
        "expected_stop": 3,
        "expected_status": "FAILED",
        "has_output": False
    },
    {
        "key": "sec_data_hi",
        "name": "sec_data_config_hi.vital",
        "path": "examples/security_lab/hindi/sec_data_config_hi.vital",
        "expected_stop": 11,
        "expected_status": "BLOCKED_BY_SECURITY",
        "has_output": False
    },
    {
        "key": "sec_injection_bn",
        "name": "sec_injection_eval_bn.vital",
        "path": "examples/security_lab/bengali/sec_injection_eval_bn.vital",
        "expected_stop": 11,
        "expected_status": "BLOCKED_BY_SECURITY",
        "has_output": False
    },
    {
        "key": "bank_ledger_hi",
        "name": "bank_ledger_system.vital",
        "path": "examples/hindi/bank_ledger_system.vital",
        "expected_stop": 14,
        "expected_status": "WARNING",
        "has_output": True
    }
]

os.makedirs("docs/screenshots", exist_ok=True)

print("Starting Playwright verification...")
with sync_playwright() as p:
    browser = p.chromium.launch(channel="msedge", headless=True)
    page = browser.new_page(viewport={"width": 1600, "height": 950})

    results = []

    for item in FILES:
        print(f"\n=======================================================")
        print(f"Testing {item['name']} ({item['path']})")
        print(f"=======================================================")

        page.goto("http://127.0.0.1:8000", wait_until="networkidle")
        page.wait_for_timeout(1000)

        # Load file via IDE API
        page.evaluate("async (p) => { await window.__VITAL_IDE__.loadDemoFile(p); }", item["path"])
        page.wait_for_timeout(1500)

        # Confirm BEFORE RUN:
        # 1. Header reads "Ready"
        status_badge = page.locator("#pipeline-status-badge").inner_text().strip()
        progress_text = page.locator("#pipeline-metric-progress").inner_text().strip()
        print(f"Before Run Status: {status_badge}, Progress: {progress_text}")

        # 2. No stage badges showing warnings/errors
        badge11_text = page.locator("#step-badge-security_analysis").inner_text().strip() if page.locator("#step-badge-security_analysis").is_visible() else "None"
        print(f"Stage 11 Badge before run: {badge11_text}")

        # 3. Health chip shows health
        chip = page.locator("#editor-health-chip")
        chip_visible = chip.is_visible()
        chip_text = chip.inner_text().strip() if chip_visible else ""
        print(f"Health Chip visible: {chip_visible}, text: '{chip_text}'")

        # 4. Panel shows Code Health tab
        health_tab_active = page.locator("#tab-btn-health").evaluate("el => el.classList.contains('active')")
        health_panel_visible = page.locator("#tab-out-health").is_visible()
        print(f"Code Health Tab active: {health_tab_active}, panel visible: {health_panel_visible}")

        # Capture Before-Run screenshot
        before_path = f"docs/screenshots/{item['key']}_before.png"
        page.screenshot(path=before_path)
        print(f"Saved before screenshot: {before_path}")

        # Click Run
        btn_run = page.locator("#btn-run")
        btn_run.click()
        print("Clicked Run button, waiting for pipeline to finish...")

        # Wait for run to finish (Run button re-enabled and status not running)
        page.wait_for_function(
            "() => { const btn = document.querySelector('#btn-run'); return btn && !btn.disabled && !document.querySelector('.pipeline-status-badge.badge-running'); }",
            timeout=25000
        )
        page.wait_for_timeout(2000)

        # Confirm AFTER RUN:
        status_after = page.locator("#pipeline-status-badge").inner_text().strip()
        progress_after = page.locator("#pipeline-metric-progress").inner_text().strip()
        header_msg = page.locator("#pipeline-header-title").inner_text().strip() if page.locator("#pipeline-header-title").is_visible() else ""
        print(f"After Run Status: {status_after}, Progress: {progress_after}")
        print(f"Header Message: {header_msg}")

        # Check output / empty state visibility
        empty_state_visible = page.locator("#output-blocked-empty-state").is_visible()
        print(f"Empty state visible: {empty_state_visible} (expected: {not item['has_output']})")

        # Capture After-Run screenshot
        after_path = f"docs/screenshots/{item['key']}_after.png"
        page.screenshot(path=after_path)
        print(f"Saved after screenshot: {after_path}")

        results.append({
            "file": item["name"],
            "before_status": status_badge,
            "before_progress": progress_text,
            "chip_text": chip_text,
            "health_tab_active": health_tab_active,
            "after_status": status_after,
            "after_progress": progress_after,
            "empty_state_visible": empty_state_visible,
            "before_screenshot": before_path,
            "after_screenshot": after_path
        })

    browser.close()

print("\n\n================ VERIFICATION SUMMARY ================")
for r in results:
    print(f"File: {r['file']}")
    print(f"  Before: Status='{r['before_status']}', Progress='{r['before_progress']}', Chip='{r['chip_text']}', HealthTabActive={r['health_tab_active']}")
    print(f"  After:  Status='{r['after_status']}', Progress='{r['after_progress']}', EmptyState={r['empty_state_visible']}")
    print(f"  Screenshots: {r['before_screenshot']} | {r['after_screenshot']}")
