# -*- coding: utf-8 -*-
import time
from playwright.sync_api import sync_playwright

def test():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto('http://127.0.0.1:8000/?file=examples/security_lab/telugu/sec_injection_eval_te.vital')
        page.wait_for_timeout(2000)
        
        # Turn AI toggle ON using JS
        page.evaluate("""() => {
            const el = document.getElementById('toggle-stage12-ai');
            if (el && !el.checked) {
                el.checked = true;
                el.dispatchEvent(new Event('change'));
            }
        }""")
        page.wait_for_timeout(500)
        
        # Click Run
        page.locator('#btn-run').click()
        
        # Wait until pipeline-status-badge text changes from RUNNING
        start_t = time.time()
        badge_text = "RUNNING"
        while time.time() - start_t < 60:
            badge_text = page.locator('#pipeline-status-badge').inner_text()
            metric_stage = page.locator('#pipeline-metric-stage').inner_text()
            print(f"[{time.time()-start_t:.1f}s] Badge: {badge_text} | Metric: {metric_stage}")
            if badge_text not in ["RUNNING", "Ready"]:
                break
            page.wait_for_timeout(2000)
            
        metric_stage = page.locator('#pipeline-metric-stage').inner_text()
        progress = page.locator('#pipeline-metric-progress').inner_text()
        preflight_msg = page.locator('#pipeline-preflight-message').inner_text() if page.locator('#pipeline-preflight-message').is_visible() else 'hidden'
        preflight_acc = page.locator('#pipeline-preflight-accuracy').inner_text() if page.locator('#pipeline-preflight-accuracy').is_visible() else 'hidden'
        
        print('\nFINAL RESULTS:')
        print('Status Badge:', badge_text)
        print('Metric Stage:', metric_stage)
        print('Metric Progress:', progress)
        print('Preflight Msg:', preflight_msg)
        print('Preflight Accuracy:', preflight_acc)
        
        stages = [
            ("source_input", "Stage 1 Source Input"),
            ("lexical_analysis", "Stage 2 Lexical Analysis"),
            ("syntax_analysis", "Stage 3 Syntax Parsing"),
            ("ast_construction", "Stage 4 AST Construction"),
            ("semantic_analysis", "Stage 5 Semantic Analysis"),
            ("symbol_table", "Stage 6 Symbol Table"),
            ("ir_generation", "Stage 7 IR Generation"),
            ("optimization", "Stage 8 Optimization"),
            ("code_generation", "Stage 9 Code Generation"),
            ("code_validation", "Stage 10 Code Validation"),
            ("security_analysis", "Stage 11 Security Analysis"),
            ("ai_security_analysis", "Stage 12 AI Security Analysis"),
            ("sandbox_execution", "Stage 13 Sandbox Execution"),
            ("final_report", "Stage 14 Final Report")
        ]
        
        for sid, name in stages:
            node = page.locator(f'#step-node-{sid}')
            if node.count() > 0:
                cls = node.get_attribute('class')
                icon = node.locator('.stepper-step-icon').inner_text()
                print(f'{name} ({sid}): class="{cls}", icon="{icon}"')
            else:
                print(f'{name} ({sid}): NOT FOUND')
                
        page.screenshot(path="reports/after_fix.png")
        print("Captured reports/after_fix.png")
        browser.close()

if __name__ == '__main__':
    test()
