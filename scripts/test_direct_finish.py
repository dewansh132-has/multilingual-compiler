import sys
sys.path.insert(0, ".")
from playwright.sync_api import sync_playwright
from web.pipeline_tracker import execute_pipeline_with_tracker
import json

code = open("examples/telugu/text_statistics_analyzer.vital", encoding="utf-8").read()
tracker = execute_pipeline_with_tracker(code, "Telugu", run_ai_security=False)
finish_event = None
while not tracker.event_queue.empty():
    it = tracker.event_queue.get()
    if it.get("event") == "pipeline_finish":
        finish_event = it

with sync_playwright() as p:
    browser = p.chromium.launch(channel="msedge", headless=True)
    page = browser.new_page()
    page_errors = []
    console_logs = []
    page.on("pageerror", lambda err: page_errors.append(str(err)))
    page.on("console", lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"))

    page.goto("http://127.0.0.1:8000")
    page.wait_for_timeout(1000)
    page.evaluate("async () => { await window.__VITAL_IDE__.loadDemoFile('examples/telugu/text_statistics_analyzer.vital'); }")
    page.wait_for_timeout(1000)

    # Set activeRunId to match event run_id so revision/run checks pass
    page.evaluate("(runId) => { window.__VITAL_IDE__.state.pipeline.activeRunId = runId; }", finish_event["run_id"])

    try:
        page.evaluate("(evt) => window.__VITAL_IDE__.handlePipelineEvent(evt)", finish_event)
        print("handlePipelineEvent returned successfully!")
    except Exception as e:
        print("handlePipelineEvent THREW:", e)

    print("Page errors:", page_errors)
    print("Console errors/warnings:", [c for c in console_logs if "[error]" in c or "[warning]" in c])
    badge = page.locator("#pipeline-status-badge").inner_text()
    print("Status badge:", badge)
    program_out = page.locator("#console-program-output").inner_text()
    print("Program output snippet:", repr(program_out[:100]))
    report = page.locator("#console-pipeline-report").inner_text()
    print("Pipeline report snippet:", repr(report[:100]))
    browser.close()
