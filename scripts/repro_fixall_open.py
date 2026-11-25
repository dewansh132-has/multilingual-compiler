# -*- coding: utf-8 -*-
"""
scripts/repro_fixall_open.py

Step 1 Reproduction probe for Fix All Issues (N) across all 79 demos.
Runs in Playwright headless mode:
1. Opens each demo fresh without running (pre-run phase).
2. Inspects Code Health panel: button presence, label N, disabled state, opacity, cursor.
3. Clicks button and records if dialog opens within 3 seconds, its title, and row count.
4. Presses Run (with AI toggle OFF), waits for run to complete (post-run phase).
5. Repeats button inspection and click check.
6. Captures all console errors, page errors, and network requests triggered.
7. Saves reports/fixall_open_audit.csv and reports/fixall_open_audit.md.
"""

import os
import sys
import time
import json
import csv
import urllib.request
import urllib.parse
import re
from playwright.sync_api import sync_playwright

BASE_URL = "http://127.0.0.1:8000"

def get_all_demos():
    resp = urllib.request.urlopen(f"{BASE_URL}/api/demos")
    data = json.loads(resp.read().decode("utf-8"))
    return data.get("data", {}).get("demos", [])

def run_audit():
    demos = get_all_demos()
    print(f"Total demos found for audit: {len(demos)}")

    os.makedirs("reports", exist_ok=True)
    csv_file = "reports/fixall_open_audit.csv"
    md_file = "reports/fixall_open_audit.md"

    fieldnames = [
        "language", "file", "category", "phase",
        "button label N", "enabled?", "dialog opened?",
        "dialog N/M", "rows", "error text"
    ]

    records = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()

        for idx, demo in enumerate(demos, start=1):
            lang = demo.get("language", "English")
            fpath = demo.get("path", "")
            fname = os.path.basename(fpath)
            category = demo.get("category", "")
            print(f"[{idx}/{len(demos)}] Auditing: {lang} | {fname} ({category})...")

            page = context.new_page()

            console_errors = []
            page_errors = []
            network_calls = []

            page.on("console", lambda msg: console_errors.append(f"[{msg.type}] {msg.text}") if msg.type in ("error", "warning") else None)
            page.on("pageerror", lambda err: page_errors.append(str(err)))
            page.on("response", lambda resp: network_calls.append(f"{resp.request.method} {resp.url} -> {resp.status}") if "/api/" in resp.url else None)

            # -----------------------------------------------------------------
            # PHASE 1: PRE-RUN
            # -----------------------------------------------------------------
            encoded_path = urllib.parse.quote(fpath)
            try:
                page.goto(f"{BASE_URL}/?file={encoded_path}", wait_until="commit", timeout=5000)
            except Exception as e:
                console_errors.append(f"goto error: {e}")

            # Wait for health analysis
            try:
                page.wait_for_selector("#health-status-text", state="attached", timeout=4000)
            except Exception:
                pass
            
            # Open Health tab
            try:
                page.click("#tab-btn-health", timeout=2000)
            except Exception as e:
                console_errors.append(f"Tab click failed: {e}")

            # Wait for button to settle out of loading state
            try:
                page.wait_for_function("() => { const b = document.getElementById('btn-health-fix-all'); return b && !b.classList.contains('loading'); }", timeout=8000)
            except Exception:
                pass

            btn = page.locator("#btn-health-fix-all")
            btn_visible = btn.is_visible()
            btn_text = btn.inner_text().strip() if btn_visible else ""
            
            label_n = 0
            match = re.search(r'\((\d+)\)', btn_text)
            if match:
                label_n = int(match.group(1))
            elif btn_visible and "Fix All" in btn_text:
                label_n = -1

            is_disabled = btn.evaluate("el => el.disabled || el.getAttribute('aria-disabled') === 'true' || el.classList.contains('disabled')") if btn_visible else True

            enabled_str = "yes" if (btn_visible and not is_disabled) else "no"

            dialog_opened = "no"
            dialog_nm = "-"
            rows_count = 0
            err_text = ""

            if btn_visible and not is_disabled and label_n > 0:
                try:
                    btn.click(timeout=2000)
                    modal = page.locator("#fix-modal-overlay")
                    try:
                        modal.wait_for(state="visible", timeout=3000)
                        dialog_opened = "yes"
                        title_el = page.locator("#fix-modal-title")
                        title_text = title_el.inner_text() if title_el.is_visible() else ""
                        m_nm = re.search(r'\((\d+/\d+[^)]*)\)', title_text)
                        dialog_nm = m_nm.group(1) if m_nm else title_text
                        cards = page.locator(".fix-error-card")
                        rows_count = cards.count()

                        # Close modal
                        close_btn = page.locator("#btn-reject-fix")
                        if close_btn.is_visible():
                            close_btn.click(timeout=1000)
                    except Exception:
                        dialog_opened = "no"
                except Exception as e:
                    err_text = f"Click exception: {e}"

            if not err_text and (console_errors or page_errors):
                err_text = "; ".join(page_errors + console_errors[:2])

            records.append({
                "language": lang,
                "file": fname,
                "category": category,
                "phase": "pre-run",
                "button label N": label_n,
                "enabled?": enabled_str,
                "dialog opened?": dialog_opened,
                "dialog N/M": dialog_nm,
                "rows": rows_count,
                "error text": err_text[:80]
            })

            # -----------------------------------------------------------------
            # PHASE 2: POST-RUN (with AI toggle OFF)
            # -----------------------------------------------------------------
            console_errors.clear()
            page_errors.clear()
            network_calls.clear()

            # Ensure AI toggle is OFF
            try:
                page.evaluate("() => { const tg = document.getElementById('toggle-stage12-ai'); if (tg) tg.checked = false; }")
            except Exception:
                pass

            # Click Run
            btn_run = page.locator("#btn-run")
            if btn_run.is_visible():
                try:
                    btn_run.click(timeout=2000)
                except Exception:
                    pass

            # Wait for execution to settle (up to 10s)
            try:
                page.wait_for_function("() => { const b = document.getElementById('pipeline-status-badge'); return b && !b.textContent.includes('RUNNING'); }", timeout=10000)
            except Exception:
                pass

            # Close stage drawer if opened by pause/stop, then switch back to Health tab
            try:
                page.keyboard.press("Escape")
                time.sleep(0.2)
                page.click("#tab-btn-health", timeout=2000)
            except Exception:
                pass

            # Wait for button to settle out of loading state
            try:
                page.wait_for_function("() => { const b = document.getElementById('btn-health-fix-all'); return b && !b.classList.contains('loading'); }", timeout=8000)
            except Exception:
                pass

            btn = page.locator("#btn-health-fix-all")
            btn_visible = btn.is_visible()
            btn_text = btn.inner_text().strip() if btn_visible else ""
            label_n = 0
            match = re.search(r'\((\d+)\)', btn_text)
            if match:
                label_n = int(match.group(1))

            is_disabled = btn.evaluate("el => el.disabled || el.getAttribute('aria-disabled') === 'true' || el.classList.contains('disabled')") if btn_visible else True
            enabled_str = "yes" if (btn_visible and not is_disabled) else "no"

            dialog_opened = "no"
            dialog_nm = "-"
            rows_count = 0
            err_text = ""

            if btn_visible and not is_disabled and label_n > 0:
                try:
                    btn.click(timeout=2000)
                    modal = page.locator("#fix-modal-overlay")
                    try:
                        modal.wait_for(state="visible", timeout=3000)
                        dialog_opened = "yes"
                        title_el = page.locator("#fix-modal-title")
                        title_text = title_el.inner_text() if title_el.is_visible() else ""
                        m_nm = re.search(r'\((\d+/\d+[^)]*)\)', title_text)
                        dialog_nm = m_nm.group(1) if m_nm else title_text
                        cards = page.locator(".fix-error-card")
                        rows_count = cards.count()

                        close_btn = page.locator("#btn-reject-fix")
                        if close_btn.is_visible():
                            close_btn.click(timeout=1000)
                    except Exception:
                        dialog_opened = "no"
                except Exception as e:
                    err_text = f"Click exception: {e}"

            if not err_text and (console_errors or page_errors):
                err_text = "; ".join(page_errors + console_errors[:2])

            records.append({
                "language": lang,
                "file": fname,
                "category": category,
                "phase": "post-run",
                "button label N": label_n,
                "enabled?": enabled_str,
                "dialog opened?": dialog_opened,
                "dialog N/M": dialog_nm,
                "rows": rows_count,
                "error text": err_text[:80]
            })

            # Close page to cleanly tear down EventSource
            try:
                page.close()
            except Exception:
                pass

        browser.close()

    # Write CSV
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    # Write Markdown
    with open(md_file, "w", encoding="utf-8") as f:
        f.write("# Fix All Open Audit Report (Pre-Fix Reproduction)\n\n")
        f.write(f"Total Rows: {len(records)} (79 demos x 2 phases)\n\n")
        f.write("| " + " | ".join(fieldnames) + " |\n")
        f.write("| " + " | ".join(["---"] * len(fieldnames)) + " |\n")
        for r in records:
            vals = [str(r[k]) for k in fieldnames]
            f.write("| " + " | ".join(vals) + " |\n")

    print(f"Audit completed: {csv_file} and {md_file} written successfully.")

if __name__ == "__main__":
    run_audit()
