#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scripts/audit_counts.py — Comprehensive Headless Playwright Audit of All 79 Demos

Runs every demo in the explorer (all 79, all 7 languages, all categories):
- Fresh load (no edits, forceRestore=true)
- Runs with AI toggle OFF
- Waits for run to finish
- Records:
  a. Each stage badge number in pipeline strip (stages 1-14)
  b. Each stage dialog's "Findings / Warnings" metric, the "N ISSUES DETECTED" pill,
     number of finding cards actually rendered, and dialog header status pill
  c. Preflight strip numbers ("Security: N findings (M high)")
  d. Health chip score, Code Health panel (status, insecure %, dead code %, error density, Fix All (N))
  e. After clicking Fix All Issues (N): dialog title N/M, number of issue rows rendered, primary button label
  f. Backend collection sizes for the same file (stages 1-14 findings, health errors, security, dead code, fixable)
  g. Compares and flags all disagreements in MISMATCH column
Writes:
  reports/count_audit.csv
  reports/count_audit.md
Prints:
  List of mismatching files at the end.
"""

import csv
import json
import os
import re
import sys
import time
from typing import Dict, List, Any, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from playwright.sync_api import sync_playwright
import web.demo_manager as dm
from web.code_health import analyze_health

STAGE_IDS = [
    "source_input",
    "lexical_analysis",
    "syntax_analysis",
    "ast_construction",
    "semantic_analysis",
    "symbol_table",
    "ir_generation",
    "optimization",
    "code_generation",
    "code_validation",
    "security_analysis",
    "ai_security_analysis",
    "sandbox_execution",
    "final_report"
]

def parse_int_safe(val: Any) -> Optional[int]:
    if val is None:
        return None
    s = str(val).strip()
    m = re.search(r'\d+', s)
    return int(m.group(0)) if m else None

def run_audit(out_csv: Optional[str] = None, out_md: Optional[str] = None, filter_str: str = "", limit: Optional[int] = None):
    os.makedirs(os.path.join(PROJECT_ROOT, "reports"), exist_ok=True)
    all_demos_data = dm.get_all_demos()
    demos = all_demos_data.get("demos", [])
    if filter_str:
        demos = [d for d in demos if filter_str in d["path"]]
    if limit:
        demos = demos[:limit]
    total_demos = len(demos)
    print(f"Discovered {total_demos} demos across all categories.")

    audit_rows: List[Dict[str, Any]] = []

    print("Launching Chromium (headless)...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, channel="chrome")
        page = browser.new_page(viewport={"width": 1600, "height": 950})

        # Navigate to IDE
        page.goto("http://127.0.0.1:8000", wait_until="networkidle")
        page.wait_for_selector("#demo-tree", timeout=15000)

        # Ensure AI toggle is OFF
        toggle_ai = page.query_selector("#toggle-stage12-ai")
        if toggle_ai and page.evaluate("el => el.checked", toggle_ai):
            page.evaluate("el => { el.checked = false; el.dispatchEvent(new Event('change')); }", toggle_ai)
            page.wait_for_timeout(300)

        for idx, demo in enumerate(demos, start=1):
            rel_path = demo["path"]
            lang = demo.get("language", "English")
            cat = demo.get("category", "")
            fname = os.path.basename(rel_path)
            print(f"[{idx:2d}/{total_demos}] Auditing: {rel_path} ({lang}) ...", flush=True)

            # Load file directly from disk / pristine fixture via window.__VITAL_IDE__.loadDemoFile
            page.evaluate("""async (path) => {
                if (window.__VITAL_IDE__ && window.__VITAL_IDE__.closeStageDrawer) {
                    window.__VITAL_IDE__.closeStageDrawer();
                }
                const bd = document.getElementById('stage-overlay-backdrop');
                if (bd) bd.style.display = 'none';
                const mo = document.getElementById('fix-modal-overlay');
                if (mo) mo.style.display = 'none';
                await window.__VITAL_IDE__.loadDemoFile(path, true);
            }""", rel_path)
            page.wait_for_timeout(400)

            # Click Run with AI toggle OFF
            page.evaluate("""() => {
                const b = document.getElementById('btn-run');
                if (b) b.click();
            }""")
            page.wait_for_timeout(300)

            # Wait for execution to finish
            try:
                page.wait_for_function(
                    "() => !window.__VITAL_IDE__.state.isExecuting",
                    timeout=20000
                )
            except Exception as e:
                print(f"  Warning: Run timed out waiting for execution to finish for {rel_path}")

            page.wait_for_timeout(400)

            # -------------------------------------------------------------
            # a. Pipeline Strip Stage Badges (stages 1-14)
            # -------------------------------------------------------------
            stage_badges = page.evaluate("""() => {
                const res = {};
                for (let i = 1; i <= 14; i++) {
                    const def = window.__VITAL_IDE__.state.pipeline.stages[i - 1];
                    const el = document.getElementById(`step-badge-${def.id}`);
                    res[def.id] = el ? el.textContent.trim() : "";
                }
                return res;
            }""")

            # -------------------------------------------------------------
            # b. Stage Dialog Details (stages 1-14)
            # -------------------------------------------------------------
            dialog_stats = page.evaluate("""() => {
                const res = {};
                const stages = window.__VITAL_IDE__.state.pipeline.stages || [];
                for (const st of stages) {
                    const node = document.getElementById(`step-node-${st.id}`);
                    if (node) node.click();

                    let findingsMetric = null;
                    document.querySelectorAll(".drawer-stat-card").forEach(c => {
                        const lbl = c.querySelector(".drawer-stat-label");
                        if (lbl && lbl.textContent.includes("Findings / Warnings")) {
                            findingsMetric = c.querySelector(".drawer-stat-value")?.textContent?.trim() || "0";
                        }
                    });
                    const pill = document.querySelector(".stage-findings-count-badge")?.textContent?.trim() || "";
                    const cardsCount = document.querySelectorAll(".stage-finding-card")?.length || 0;
                    const statusPill = document.querySelector(".drawer-status-pill")?.textContent?.trim() || "";
                    res[st.id] = { findingsMetric, pill, cardsCount, statusPill };
                }
                if (window.__VITAL_IDE__ && window.__VITAL_IDE__.closeStageDrawer) {
                    window.__VITAL_IDE__.closeStageDrawer();
                }
                const bd = document.getElementById("stage-overlay-backdrop");
                if (bd) bd.style.display = "none";
                return res;
            }""")

            # -------------------------------------------------------------
            # c. Preflight Strip Numbers
            # -------------------------------------------------------------
            preflight_info = page.evaluate("""() => {
                const strip = document.getElementById("pipeline-preflight-strip");
                const msg = document.getElementById("pipeline-preflight-message")?.textContent?.trim() || "";
                return {
                    visible: strip ? (strip.style.display !== "none") : false,
                    text: msg
                };
            }""")
            p_text = preflight_info.get("text", "")
            sec_m = re.search(r'Security:\s*(\d+)\s*findings?(?:\s*\((\d+)\s*high\))?', p_text)
            preflight_sec_count = int(sec_m.group(1)) if sec_m else 0
            preflight_high_count = int(sec_m.group(2)) if (sec_m and sec_m.group(2)) else 0

            # -------------------------------------------------------------
            # d. Health Chip Score & Code Health Panel
            # -------------------------------------------------------------
            page.evaluate("""() => {
                const bd = document.getElementById('stage-overlay-backdrop');
                if (bd) bd.style.display = 'none';
                const tb = document.getElementById('tab-btn-health');
                if (tb) tb.click();
            }""")
            page.wait_for_timeout(300)

            health_ui = page.evaluate("""() => {
                const score = document.getElementById("health-score-number")?.textContent?.trim() || "";
                const status = document.getElementById("health-status-text")?.textContent?.trim() || "";
                const insec = document.getElementById("health-val-insecure")?.textContent?.trim() || "";
                const dead = document.getElementById("health-val-deadcode")?.textContent?.trim() || "";
                const density = document.getElementById("health-val-density")?.textContent?.trim() || "";
                const btnFix = document.getElementById("btn-health-fix-all");
                const btnVisible = btnFix ? (btnFix.style.display !== "none" && !btnFix.disabled) : false;
                const btnText = btnFix ? btnFix.textContent.trim() : "";
                return { score, status, insec, dead, density, btnVisible, btnText };
            }""")

            fix_btn_text = health_ui.get("btnText", "")
            btn_fix_n = 0
            if health_ui.get("btnVisible") and "Fix All Issues" in fix_btn_text:
                m_btn = re.search(r'\((\d+)\)', fix_btn_text)
                if m_btn:
                    btn_fix_n = int(m_btn.group(1))

            # -------------------------------------------------------------
            # e. Fix All Dialog (if button is visible with N > 0)
            # -------------------------------------------------------------
            fix_dialog_info = {
                "title": "",
                "resolved_n": None,
                "total_m": None,
                "rows_rendered": 0,
                "primary_btn": ""
            }

            if health_ui.get("btnVisible") and btn_fix_n > 0:
                try:
                    page.evaluate("() => document.getElementById('btn-health-fix-all').click()")
                    page.wait_for_function("() => { const el = document.getElementById('fix-modal-overlay'); return el && (el.style.display === 'flex' || el.style.display === 'block'); }", timeout=45000)
                    page.wait_for_timeout(600)

                    d_info = page.evaluate("""() => {
                        const title = document.getElementById("fix-modal-title")?.textContent?.trim() || "";
                        const rows = document.querySelectorAll(".fix-error-card")?.length || 0;
                        const btnLabel = document.getElementById("btn-apply-fix")?.textContent?.trim() || "";
                        return { title, rows, btnLabel };
                    }""")
                    fix_dialog_info["title"] = d_info["title"]
                    fix_dialog_info["rows_rendered"] = d_info["rows"]
                    fix_dialog_info["primary_btn"] = d_info["btnLabel"]

                    # Extract N/M from title
                    m_title = re.search(r'\((\d+)/(\d+)\s+Issues Resolved\)', d_info["title"])
                    if m_title:
                        fix_dialog_info["resolved_n"] = int(m_title.group(1))
                        fix_dialog_info["total_m"] = int(m_title.group(2))

                    # Close modal
                    page.evaluate("""() => {
                        const closeBtn = document.getElementById("btn-close-fix-modal");
                        if (closeBtn) closeBtn.click();
                        const mo = document.getElementById("fix-modal-overlay");
                        if (mo) mo.style.display = "none";
                    }""")
                    page.wait_for_timeout(200)
                except Exception as ex:
                    print(f"  Warning: Fix modal failed on {rel_path}: {ex}")
                    page.evaluate("""() => {
                        const mo = document.getElementById("fix-modal-overlay");
                        if (mo) mo.style.display = "none";
                    }""")

            # -------------------------------------------------------------
            # f. Backend Collection Sizes
            # -------------------------------------------------------------
            full_code_path = os.path.join(PROJECT_ROOT, rel_path)
            content = ""
            if os.path.isfile(full_code_path):
                with open(full_code_path, "r", encoding="utf-8", errors="replace") as cf:
                    content = cf.read()

            b_health = analyze_health(content, language=lang, filename=fname)
            b_errors_cnt = len(b_health.get("errors", []))
            b_sec_cnt = len(b_health.get("security", {}).get("findings", []))
            b_dead_cnt = len(b_health.get("dead_code", {}).get("items", []))
            b_fixable_cnt = b_health.get("fixable_count", 0)

            # Read pipeline backend stage findings from browser state
            backend_stage_findings = page.evaluate("""() => {
                const res = {};
                const stData = (window.__VITAL_IDE__.state.pipeline && window.__VITAL_IDE__.state.pipeline.stageData) || {};
                for (const sid of Object.keys(stData)) {
                    const st = stData[sid];
                    const findings = (st.details && Array.isArray(st.details.findings)) ? st.details.findings : [];
                    res[sid] = {
                        status: st.status || "pending",
                        findings_count: findings.length
                    };
                }
                return res;
            }""")

            # -------------------------------------------------------------
            # g. Compare and Detect Disagreements (Mismatches)
            # -------------------------------------------------------------
            mismatches: List[str] = []

            # 1. Badge vs Drawer Findings Metric vs Cards
            for s_id in STAGE_IDS:
                badge_str = stage_badges.get(s_id, "")
                badge_num = parse_int_safe(badge_str)
                d_metric_str = dialog_stats.get(s_id, {}).get("findingsMetric")
                d_metric_num = parse_int_safe(d_metric_str)
                d_cards = dialog_stats.get(s_id, {}).get("cardsCount", 0)
                d_status = dialog_stats.get(s_id, {}).get("statusPill", "")

                b_status = backend_stage_findings.get(s_id, {}).get("status", "")
                b_findings = backend_stage_findings.get(s_id, {}).get("findings_count", 0)

                # Check if stage passed but drawer says Pending
                if b_status in ("passed", "completed") and "Pending" in d_status:
                    mismatches.append(f"{s_id}: Passed stage displayed as 'Pending - In Queue'")

                # Check if badge count disagrees with drawer metric or cards
                if badge_num is not None and d_metric_num is not None:
                    if badge_num != d_metric_num:
                        mismatches.append(f"{s_id}: Badge ({badge_num}) != Dialog Metric ({d_metric_num})")
                    if d_metric_num != d_cards and d_metric_num > 0:
                        mismatches.append(f"{s_id}: Dialog Metric ({d_metric_num}) != Rendered Cards ({d_cards})")

            # 2. Preflight Security count vs Code Health Security findings vs Stage 11 Findings
            s11_findings_cnt = backend_stage_findings.get("security_analysis", {}).get("findings_count", 0)
            if preflight_sec_count != b_sec_cnt:
                mismatches.append(f"Preflight Sec ({preflight_sec_count}) != Code Health Sec ({b_sec_cnt})")
            if b_sec_cnt != s11_findings_cnt and s11_findings_cnt > 0:
                mismatches.append(f"Code Health Sec ({b_sec_cnt}) != Stage 11 Findings ({s11_findings_cnt})")

            # 3. Fix All Button (N) vs Backend Fixable count vs Dialog Title (N/M) vs Rendered Rows
            if btn_fix_n > 0:
                if btn_fix_n != b_fixable_cnt:
                    mismatches.append(f"Fix All Button ({btn_fix_n}) != Backend Fixable ({b_fixable_cnt})")
                if fix_dialog_info["total_m"] is not None and fix_dialog_info["total_m"] != btn_fix_n:
                    mismatches.append(f"Fix All Button ({btn_fix_n}) != Fix Dialog Total ({fix_dialog_info['total_m']})")
                if fix_dialog_info["total_m"] is not None and fix_dialog_info["total_m"] != fix_dialog_info["rows_rendered"]:
                    mismatches.append(f"Fix Dialog Total ({fix_dialog_info['total_m']}) != Rendered Rows ({fix_dialog_info['rows_rendered']})")

            # 4. Lexer Stage 2 warnings vs Preflight/Health security findings (Homoglyph leak)
            s2_findings = backend_stage_findings.get("lexical_analysis", {}).get("findings_count", 0)
            if s2_findings > 0 and preflight_sec_count == s2_findings and s11_findings_cnt == 0:
                mismatches.append(f"Stage 2 Lexer Warning ({s2_findings}) counted as Preflight Security Finding ({preflight_sec_count})")

            row_data = {
                "path": rel_path,
                "language": lang,
                "category": cat,
                "overall_status": page.evaluate("() => document.getElementById('pipeline-status-badge')?.textContent?.trim() || ''"),
                # Badges
                **{f"badge_{s}": stage_badges.get(s, "") for s in STAGE_IDS},
                # Dialog Metrics
                **{f"dialog_{s}_metric": dialog_stats.get(s, {}).get("findingsMetric", "") for s in STAGE_IDS},
                **{f"dialog_{s}_pill": dialog_stats.get(s, {}).get("pill", "") for s in STAGE_IDS},
                **{f"dialog_{s}_cards": dialog_stats.get(s, {}).get("cardsCount", 0) for s in STAGE_IDS},
                **{f"dialog_{s}_status": dialog_stats.get(s, {}).get("statusPill", "") for s in STAGE_IDS},
                # Preflight
                "preflight_sec_findings": preflight_sec_count,
                "preflight_high_findings": preflight_high_count,
                "preflight_text": p_text,
                # Health Panel
                "health_score": health_ui.get("score", ""),
                "health_status": health_ui.get("status", ""),
                "health_insecure_pct": health_ui.get("insec", ""),
                "health_dead_code_pct": health_ui.get("dead", ""),
                "health_error_density": health_ui.get("density", ""),
                "health_fix_all_btn_n": btn_fix_n,
                # Fix Dialog
                "fix_dialog_title": fix_dialog_info["title"],
                "fix_dialog_resolved_n": fix_dialog_info["resolved_n"],
                "fix_dialog_total_m": fix_dialog_info["total_m"],
                "fix_dialog_rows_rendered": fix_dialog_info["rows_rendered"],
                "fix_dialog_primary_btn": fix_dialog_info["primary_btn"],
                # Backend Collections
                **{f"backend_{s}_findings": backend_stage_findings.get(s, {}).get("findings_count", 0) for s in STAGE_IDS},
                "backend_health_errors": b_errors_cnt,
                "backend_health_security": b_sec_cnt,
                "backend_health_dead_code": b_dead_cnt,
                "backend_health_fixable": b_fixable_cnt,
                # Mismatches
                "has_mismatch": "YES" if len(mismatches) > 0 else "NO",
                "mismatches": "; ".join(mismatches)
            }
            audit_rows.append(row_data)

        browser.close()

    # -----------------------------------------------------------------
    # Write reports/count_audit.csv
    # -----------------------------------------------------------------
    # Write CSV
    # -----------------------------------------------------------------
    csv_path = out_csv or os.path.join(PROJECT_ROOT, "reports", "count_audit.csv")
    fieldnames = list(audit_rows[0].keys())
    with open(csv_path, "w", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=fieldnames)
        writer.writeheader()
        for r in audit_rows:
            writer.writerow(r)
    print(f"\nWritten {len(audit_rows)} rows to {csv_path}")

    # -----------------------------------------------------------------
    # Write Markdown
    # -----------------------------------------------------------------
    md_path = out_md or os.path.join(PROJECT_ROOT, "reports", "count_audit.md")
    mismatched_files = [r for r in audit_rows if r["has_mismatch"] == "YES"]

    with open(md_path, "w", encoding="utf-8") as mf:
        mf.write("# VITAL Cross-UI Number Consistency Audit Report\n\n")
        mf.write(f"**Total Demos Audited:** {len(audit_rows)}  \n")
        mf.write(f"**Clean Consistent Demos:** {len(audit_rows) - len(mismatched_files)}  \n")
        mf.write(f"**Demos with Disagreements (Mismatches):** {len(mismatched_files)}  \n\n")

        mf.write("## 1. Summary of Identified Disagreements\n\n")
        mf.write("| # | File Path | Language | Category | Overall Status | Mismatch Description |\n")
        mf.write("|---|-----------|----------|----------|----------------|----------------------|\n")
        for i, m in enumerate(mismatched_files, 1):
            mf.write(f"| {i} | `{m['path']}` | {m['language']} | {m['category']} | {m['overall_status']} | {m['mismatches']} |\n")

        mf.write("\n## 2. Detailed Per-Demo Audit Table\n\n")
        mf.write("| File Path | Status | Preflight Sec | Health Score | Dead Code % | Fix All Btn | Fix Dialog (Res/Tot) | Mismatch? |\n")
        mf.write("|-----------|--------|---------------|--------------|-------------|-------------|----------------------|-----------|\n")
        for r in audit_rows:
            fix_diag = f"{r['fix_dialog_resolved_n']}/{r['fix_dialog_total_m']}" if r['fix_dialog_total_m'] is not None else "-"
            mf.write(f"| `{r['path']}` | {r['overall_status']} | {r['preflight_sec_findings']} ({r['preflight_high_findings']} high) | {r['health_score']} | {r['health_dead_code_pct']} | {r['health_fix_all_btn_n']} | {fix_diag} | **{r['has_mismatch']}** |\n")

    print(f"Written markdown summary to {md_path}")

    print("\n=======================================================")
    print("MISMATCHING FILES SUMMARY")
    print("=======================================================")
    print(f"Total mismatching files: {len(mismatched_files)}")
    for m in mismatched_files:
        print(f" - {m['path']} ({m['language']}): {m['mismatches']}")
    print("=======================================================\n")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="VITAL Playwright Count Audit")
    parser.add_argument("--output-csv", default=None, help="Path for CSV report")
    parser.add_argument("--output-md", default=None, help="Path for Markdown report")
    parser.add_argument("--filter", default="", help="Filter demo paths")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of demos")
    args = parser.parse_args()
    run_audit(out_csv=args.output_csv, out_md=args.output_md, filter_str=args.filter, limit=args.limit)
