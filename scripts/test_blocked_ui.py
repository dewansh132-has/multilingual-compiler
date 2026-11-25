# -*- coding: utf-8 -*-
from playwright.sync_api import sync_playwright

def test():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.on('console', lambda msg: print('PAGE LOG:', msg.text))
        page.goto('http://127.0.0.1:8000/?file=examples/security_lab/english/sec_business_workflow.vital', wait_until='networkidle')
        page.wait_for_timeout(2000)
        btn_run = page.wait_for_selector('#btn-run')
        btn_run.click()
        page.wait_for_timeout(4000)
        
        info = page.evaluate("""() => {
            const emptyState = document.getElementById('output-blocked-empty-state');
            return {
                style: emptyState ? emptyState.getAttribute('style') : null,
                display: emptyState ? window.getComputedStyle(emptyState).display : null,
                parentDisplay: emptyState && emptyState.parentElement ? window.getComputedStyle(emptyState.parentElement).display : null,
                activeTab: document.querySelector('.output-tab-btn.active') ? document.querySelector('.output-tab-btn.active').id : null
            };
        }""")
        print('INFO:', info)
        browser.close()

if __name__ == '__main__':
    test()
