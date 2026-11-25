import os
import sys
import json
import time
import urllib.request
from playwright.sync_api import sync_playwright

BASE_URL = "http://127.0.0.1:8000"
FILE_PATH = "examples/telugu/text_statistics_analyzer.vital"

INIT_SCRIPT = """
window.__SSE_EVENTS__ = [];
window.__STREAM_ERRORS__ = [];
window.__EVENT_HANDLER_ERRORS__ = [];

const origFetch = window.fetch;
window.fetch = async function(...args) {
    const res = await origFetch.apply(this, args);
    const url = args[0] || "";
    if (typeof url === "string" && url.includes("/api/pipeline/stream")) {
        const [stream1, stream2] = res.body.tee();
        (async () => {
            const reader = stream2.getReader();
            const decoder = new TextDecoder("utf-8");
            let buffer = "";
            let order = 0;
            try {
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    buffer += decoder.decode(value, { stream: true });
                    const parts = buffer.split(/\\r?\\n\\r?\\n/);
                    buffer = parts.pop() || "";
                    for (const part of parts) {
                        const lines = part.split(/\\r?\\n/);
                        for (const line of lines) {
                            const trimmed = line.trim();
                            if (trimmed.startsWith("data:")) {
                                order++;
                                const raw = trimmed.substring(5).trim();
                                try {
                                    const parsed = JSON.parse(raw);
                                    window.__SSE_EVENTS__.push({
                                        order: order,
                                        event: parsed.event || parsed.type || "unknown",
                                        run_id: parsed.run_id || null,
                                        size: raw.length,
                                        payload: parsed
                                    });
                                } catch (e) {
                                    window.__SSE_EVENTS__.push({
                                        order: order,
                                        event: "unparseable",
                                        run_id: null,
                                        size: raw.length,
                                        raw: raw
                                    });
                                }
                            }
                        }
                    }
                }
            } catch (err) {
                window.__STREAM_ERRORS__.push(String(err));
            }
        })();

        return new Response(stream1, {
            status: res.status,
            statusText: res.statusText,
            headers: res.headers
        });
    }
    return res;
};
"""

def run_test_case(browser, file_path, ai_toggle_on, case_label):
    page = browser.new_page(viewport={"width": 1600, "height": 950})
    
    page_errors = []
    console_logs = []

    page.on("pageerror", lambda err: page_errors.append(str(err)))
    page.on("console", lambda msg: console_logs.append({
        "type": msg.type,
        "text": msg.text,
        "location": msg.location
    }))

    page.add_init_script(INIT_SCRIPT)

    print(f"\n--- Testing {case_label}: {file_path} (AI toggle: {'ON' if ai_toggle_on else 'OFF'}) ---")
    page.goto(BASE_URL, wait_until="networkidle")
    page.wait_for_timeout(1000)

    # Load file
    page.evaluate("async (p) => { await window.__VITAL_IDE__.loadDemoFile(p); }", file_path)
    page.wait_for_timeout(1500)

    # Toggle AI
    page.evaluate("(on) => { const el = document.getElementById('toggle-stage12-ai'); if (el) { el.checked = on; el.dispatchEvent(new Event('change')); } }", ai_toggle_on)
    print(f"Set AI toggle to {ai_toggle_on}")

    # Hook handlePipelineEvent if available to capture errors swallowed by catch (parseErr)
    page.evaluate("""() => {
        if (window.__VITAL_IDE__ && window.__VITAL_IDE__.handlePipelineEvent) {
            const orig = window.__VITAL_IDE__.handlePipelineEvent;
            window.__VITAL_IDE__.handlePipelineEvent = function(event) {
                try {
                    return orig.apply(this, arguments);
                } catch (e) {
                    window.__EVENT_HANDLER_ERRORS__.push({
                        message: e.message,
                        stack: e.stack,
                        event_type: event ? event.event : null
                    });
                    console.error("VITAL_EVENT_HANDLER_ERROR:", e.message, e.stack);
                    throw e;
                }
            };
        }
    }""")

    # Record initial state
    status_before = page.locator("#pipeline-status-badge").inner_text().strip()
    print(f"Initial Status Badge: {status_before}")

    # Click Run
    print("Clicking Run...")
    page.locator("#btn-run").click()

    # Wait up to 60s for run to either finish or stick
    start_time = time.time()
    last_event_count = 0
    stable_count_cycles = 0

    while time.time() - start_time < 60:
        page.wait_for_timeout(1000)
        curr_status = page.locator("#pipeline-status-badge").inner_text().strip()
        metric_stage = page.locator("#pipeline-metric-stage").inner_text().strip() if page.locator("#pipeline-metric-stage").is_visible() else ""
        events_len = page.evaluate("() => (window.__SSE_EVENTS__ || []).length")
        
        # Check if events stopped arriving
        if events_len == last_event_count and events_len > 0:
            stable_count_cycles += 1
        else:
            stable_count_cycles = 0
        last_event_count = events_len

        # If run is completed/failed/warning/paused, or stable for 6 seconds
        if curr_status not in ("RUNNING", "Ready", "Running...") and events_len > 0:
            print(f"Run reached non-running status: '{curr_status}' after {time.time() - start_time:.1f}s")
            page.wait_for_timeout(2000)
            break

        if stable_count_cycles >= 6:
            print(f"Stream has been idle for 6 seconds at stage '{metric_stage}' status '{curr_status}' with {events_len} events. Breaking wait.")
            break

    # Gather data from page
    sse_events = page.evaluate("() => window.__SSE_EVENTS__ || []")
    stream_errors = page.evaluate("() => window.__STREAM_ERRORS__ || []")
    handler_errors = page.evaluate("() => window.__EVENT_HANDLER_ERRORS__ || []")
    
    header_status = page.locator("#pipeline-status-badge").inner_text().strip()
    header_stage = page.locator("#pipeline-metric-stage").inner_text().strip() if page.locator("#pipeline-metric-stage").is_visible() else ""
    header_progress = page.locator("#pipeline-metric-progress").inner_text().strip() if page.locator("#pipeline-metric-progress").is_visible() else ""
    header_time = page.locator("#pipeline-metric-time").inner_text().strip() if page.locator("#pipeline-metric-time").is_visible() else ""

    # Output tab contents
    program_out_text = page.locator("#console-program-output").inner_text()
    pipeline_report_text = page.locator("#console-pipeline-report").inner_text()
    preflight_indicator = page.locator("#preflight-prediction-indicator").inner_text() if page.locator("#preflight-prediction-indicator").is_visible() else "Not visible"

    # IDE internal state
    ide_state = page.evaluate("""() => {
        if (!window.__VITAL_IDE__ || !window.__VITAL_IDE__.state) return null;
        const s = window.__VITAL_IDE__.state;
        return {
            activeRunId: s.pipeline ? s.pipeline.activeRunId : null,
            lastCompletedRunId: s.pipeline ? s.pipeline.lastCompletedRunId : null,
            isFinished: s.pipeline ? s.pipeline.isFinished : null,
            finishStatus: s.pipeline ? s.pipeline.finishStatus : null,
            activeDrawerStage: s.pipeline ? s.pipeline.activeDrawerStage : null,
            stageData: s.pipeline ? s.pipeline.stageData : null
        };
    }""")

    # Find the run_id from events
    run_id = None
    for evt in reversed(sse_events):
        if evt.get("run_id"):
            run_id = evt["run_id"]
            break

    # Call GET /api/runs/<run_id>
    server_run_data = None
    if run_id:
        try:
            req = urllib.request.Request(f"{BASE_URL}/api/runs/{run_id}")
            with urllib.request.urlopen(req) as resp:
                server_run_data = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            server_run_data = {"fetch_error": str(e)}

    page.close()

    result = {
        "case_label": case_label,
        "file_path": file_path,
        "ai_toggle_on": ai_toggle_on,
        "header_status": header_status,
        "header_stage": header_stage,
        "header_progress": header_progress,
        "header_time": header_time,
        "program_output_snippet": program_out_text[:300],
        "pipeline_report_snippet": pipeline_report_text[:300],
        "preflight_indicator": preflight_indicator,
        "page_errors": page_errors,
        "console_errors_warnings": [c for c in console_logs if c["type"] in ("error", "warning")],
        "handler_errors": handler_errors,
        "stream_errors": stream_errors,
        "sse_event_summary": [
            {"order": e["order"], "event": e["event"], "run_id": e["run_id"], "size": e["size"]}
            for e in sse_events
        ],
        "has_pipeline_finish_event": any(e["event"] in ("pipeline_finish", "pipeline_paused") for e in sse_events),
        "finish_event_payload": next((e["payload"] for e in sse_events if e["event"] == "pipeline_finish"), None),
        "ide_state": ide_state,
        "server_run_data": server_run_data
    }

    return result

def main():
    os.makedirs("reports", exist_ok=True)
    all_results = {}

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)

        # 1. Telugu with AI ON
        res_te_ai_on = run_test_case(browser, FILE_PATH, True, "telugu_ai_on")
        all_results["telugu_ai_on"] = res_te_ai_on

        # 2. Telugu with AI OFF
        res_te_ai_off = run_test_case(browser, FILE_PATH, False, "telugu_ai_off")
        all_results["telugu_ai_off"] = res_te_ai_off

        # 3. 4 other clean demos
        other_clean = [
            ("hindi_clean", "examples/hindi/bank_ledger_system.vital"),
            ("bengali_clean", "examples/bengali/ecommerce_order_processor.vital"),
            ("marathi_clean", "examples/marathi/cryptography_cipher_toolkit.vital"),
            ("english_clean", "examples/english/graph_shortest_path.vital")
        ]
        for label, path in other_clean:
            res = run_test_case(browser, path, False, label)
            all_results[label] = res

        # 4. One Security Lab demo
        res_sec = run_test_case(browser, "examples/security_lab/telugu/sec_business_workflow_te.vital", False, "sec_lab_te")
        all_results["sec_lab_te"] = res_sec

        browser.close()

    # Save to reports/finish_trace.json
    with open("reports/finish_trace.json", "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    
    print("\nSaved full trace to reports/finish_trace.json")

    # Print summary of Telugu AI ON
    t_on = all_results["telugu_ai_on"]
    print("\n================== TELUGU AI ON SUMMARY ==================")
    print(f"Header Status: {t_on['header_status']}")
    print(f"Header Stage: {t_on['header_stage']}")
    print(f"Program Output: {t_on['program_output_snippet']}")
    print(f"Pipeline Report: {t_on['pipeline_report_snippet']}")
    print(f"Has pipeline_finish in SSE: {t_on['has_pipeline_finish_event']}")
    print(f"Page errors ({len(t_on['page_errors'])}): {t_on['page_errors']}")
    print(f"Console errors/warnings ({len(t_on['console_errors_warnings'])}): {t_on['console_errors_warnings']}")
    print(f"Handler errors ({len(t_on['handler_errors'])}): {t_on['handler_errors']}")
    print(f"Stream errors: {t_on['stream_errors']}")

    # Print summary of Telugu AI OFF
    t_off = all_results["telugu_ai_off"]
    print("\n================== TELUGU AI OFF SUMMARY ==================")
    print(f"Header Status: {t_off['header_status']}")
    print(f"Header Stage: {t_off['header_stage']}")
    print(f"Program Output: {t_off['program_output_snippet']}")
    print(f"Pipeline Report: {t_off['pipeline_report_snippet']}")
    print(f"Has pipeline_finish in SSE: {t_off['has_pipeline_finish_event']}")
    print(f"Page errors ({len(t_off['page_errors'])}): {t_off['page_errors']}")
    print(f"Console errors/warnings ({len(t_off['console_errors_warnings'])}): {t_off['console_errors_warnings']}")
    print(f"Handler errors ({len(t_off['handler_errors'])}): {t_off['handler_errors']}")

if __name__ == "__main__":
    main()
