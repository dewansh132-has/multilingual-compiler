import os
import sys
import time
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(
        headless=True,
        channel="chrome"
    )
    page = browser.new_page()
    page.goto("http://127.0.0.1:8000")
    print("Page title:", page.title())
    browser.close()
    print("Success!")
