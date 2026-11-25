# -*- coding: utf-8 -*-
import os
import time
from playwright.sync_api import sync_playwright

def main():
    os.makedirs("reports", exist_ok=True)
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()
        
        page.goto("http://127.0.0.1:8000/?file=examples/security_lab/telugu/sec_injection_eval_te.vital", wait_until="domcontentloaded")
        page.wait_for_timeout(2000)
        
        # Turn AI toggle ON
        ai_toggle = page.locator("#toggle-stage12-ai")
        if ai_toggle.is_visible() and not ai_toggle.is_checked():
            ai_toggle.check()
            page.wait_for_timeout(500)
            
        # Click Run
        btn_run = page.wait_for_selector("#btn-run", timeout=5000)
        btn_run.click()
        
        # Wait 4 seconds for execution to reach Stage 12 or pause
        page.wait_for_timeout(4000)
        
        # Capture before screenshot
        page.screenshot(path="reports/before_fix.png")
        print("Captured reports/before_fix.png")
        
        browser.close()

if __name__ == "__main__":
    main()
