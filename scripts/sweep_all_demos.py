#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
scripts/sweep_all_demos.py — Multi-stage Compiler & Code Health Audit Sweep

Sweeps every .vital file under examples/ outside security_lab/ (and optionally security_lab/),
running stages 1-14 (AI toggle OFF) plus the Code Health analyzer.
Outputs a structured CSV and markdown table:
language | file | category | final status | stage | severity | rule code | line:col |
message | flagged text | codepoints (U+XXXX) of flagged chars | full original line
"""

import os
import sys
import csv
import re
import argparse
from typing import List, Dict, Any, Tuple

# Reconfigure stdout/stderr for Windows UTF-8 console output
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from web.pipeline_tracker import execute_pipeline_with_tracker, STAGE_ORDER
from web.code_health import analyze_health
from web.demo_manager import detect_file_language, get_all_demos


def extract_codepoints(text: str) -> str:
    """Returns space-separated hex codepoints (e.g. 'U+0964') for chars in text."""
    if not text:
        return ""
    # Filter to non-ascii or interesting characters if long, else all
    interesting = [c for c in text if ord(c) > 127]
    target = interesting if interesting else list(text[:10])
    return " ".join(f"U+{ord(c):04X}" for c in target)


def categorize_file(rel_path: str, demo_catalog: Dict[str, Any]) -> str:
    """Determines category for a given file path."""
    for demo in demo_catalog.get("demos", []):
        if demo.get("path") == rel_path or demo.get("id") == rel_path:
            return demo.get("category", "Canonical Examples")
    if "security_lab" in rel_path:
        return "Security Lab"
    if "tests" in rel_path:
        return "Cross-Language Equivalence"
    return "Canonical Examples"


def sweep_file(file_path: str, demo_catalog: Dict[str, Any]) -> List[Dict[str, Any]]:
    rel_path = os.path.relpath(file_path, PROJECT_ROOT).replace("\\", "/")
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        src = f.read()

    lines = src.splitlines()
    lang = detect_file_language(src, file_path)
    category = categorize_file(rel_path, demo_catalog)

    # 1. Run Compiler Pipeline Stages 1-14 (AI toggle OFF)
    tracker = execute_pipeline_with_tracker(
        source_code=src,
        language_hint=lang,
        run_ai_security=False,
        mandatory_only=False
    )
    final_status = tracker.compute_overall_status()

    # 2. Run Code Health Analyzer
    health = analyze_health(src, language=lang, filename=file_path)

    findings_rows: List[Dict[str, Any]] = []

    # Collect findings from pipeline stages
    for sid in STAGE_ORDER:
        st = tracker.stages.get(sid, {})
        status = st.get("status")
        stage_details = st.get("details") or {}
        stage_findings = stage_details.get("findings") or []

        # If stage failed or warned without a findings array
        if status in ("warning", "failed") and not stage_findings:
            reason = st.get("reason") or st.get("summary") or f"Stage {status}"
            findings_rows.append({
                "language": lang,
                "file": rel_path,
                "category": category,
                "final status": final_status,
                "stage": sid,
                "severity": status.upper(),
                "rule code": f"STAGE-{sid.upper()}",
                "line:col": "1:1",
                "message": reason,
                "flagged text": "",
                "codepoints (U+XXXX) of flagged chars": "",
                "full original line": lines[0] if lines else ""
            })

        for fnd in stage_findings:
            line_no = fnd.get("line") or 1
            col_no = fnd.get("column") or 1
            msg = fnd.get("title") or fnd.get("message") or fnd.get("explanation") or ""
            rule_id = fnd.get("rule_id") or fnd.get("id") or "UNKNOWN"
            sev = (fnd.get("severity") or status or "INFO").upper()

            # Flagged text / evidence
            flagged = fnd.get("evidence") or fnd.get("flagged_text") or ""
            match_chars = re.findall(r"['\"]([^'\"]+)['\"]", flagged)
            flagged_clean = match_chars[0] if match_chars else flagged

            orig_line = lines[line_no - 1].strip() if (1 <= line_no <= len(lines)) else ""
            cps = extract_codepoints(flagged_clean)

            findings_rows.append({
                "language": lang,
                "file": rel_path,
                "category": category,
                "final status": final_status,
                "stage": sid,
                "severity": sev,
                "rule code": rule_id,
                "line:col": f"{line_no}:{col_no}",
                "message": msg,
                "flagged text": flagged_clean,
                "codepoints (U+XXXX) of flagged chars": cps,
                "full original line": orig_line
            })

    # Collect Code Health errors
    for err in health.get("errors", []):
        line_no = err.get("line") or 1
        col_no = err.get("column") or 1
        orig_line = lines[line_no - 1].strip() if (1 <= line_no <= len(lines)) else ""
        msg = err.get("message") or "Code Health syntax/semantic error"
        findings_rows.append({
            "language": lang,
            "file": rel_path,
            "category": category,
            "final status": final_status,
            "stage": "code_health_errors",
            "severity": "ERROR",
            "rule code": "CH-ERR-001",
            "line:col": f"{line_no}:{col_no}",
            "message": msg,
            "flagged text": err.get("token") or "",
            "codepoints (U+XXXX) of flagged chars": extract_codepoints(err.get("token") or ""),
            "full original line": orig_line
        })

    # Collect Code Health dead code items
    for dc in health.get("dead_code", {}).get("items", []):
        line_no = dc.get("line") or 1
        orig_line = lines[line_no - 1].strip() if (1 <= line_no <= len(lines)) else ""
        name = dc.get("name") or ""
        msg = dc.get("message") or f"Dead code: {dc.get('kind')}"
        findings_rows.append({
            "language": lang,
            "file": rel_path,
            "category": category,
            "final status": final_status,
            "stage": "code_health_dead_code",
            "severity": "INFO",
            "rule code": f"CH-DEAD-{dc.get('kind', 'VAR').upper()}",
            "line:col": f"{line_no}:1",
            "message": msg,
            "flagged text": name,
            "codepoints (U+XXXX) of flagged chars": extract_codepoints(name),
            "full original line": orig_line
        })

    # If completely clean (zero findings)
    if not findings_rows:
        findings_rows.append({
            "language": lang,
            "file": rel_path,
            "category": category,
            "final status": final_status,
            "stage": "NONE",
            "severity": "CLEAN",
            "rule code": "CLEAN",
            "line:col": "-:-",
            "message": "Clean — Zero diagnostics across all stages & code health",
            "flagged text": "-",
            "codepoints (U+XXXX) of flagged chars": "-",
            "full original line": "-"
        })

    return findings_rows


def main():
    parser = argparse.ArgumentParser(description="Sweep .vital demos for diagnostics across stages 1-14 and Code Health")
    parser.add_argument("--include-security-lab", action="store_true", default=True, help="Include examples/security_lab/ in sweep (default: True)")
    parser.add_argument("--no-security-lab", action="store_true", help="Exclude examples/security_lab/ from sweep")
    parser.add_argument("--only-security-lab", action="store_true", help="Run sweep ONLY on examples/security_lab/")
    parser.add_argument("--csv-out", default=os.path.join(PROJECT_ROOT, "docs", "sweep_all_demos.csv"), help="CSV output path")
    parser.add_argument("--md-out", default=os.path.join(PROJECT_ROOT, "docs", "sweep_all_demos.md"), help="Markdown output path")
    args = parser.parse_args()

    demo_catalog = get_all_demos()

    vital_files: List[str] = []
    examples_dir = os.path.join(PROJECT_ROOT, "examples")

    for root, dirs, files in os.walk(examples_dir):
        # Exclude saved working copies
        if "saved" in root.split(os.sep):
            continue
        is_sec = "security_lab" in root.split(os.sep)
        if args.only_security_lab and not is_sec:
            continue
        if args.no_security_lab and is_sec:
            continue

        for f in sorted(files):
            if f.endswith(".vital"):
                vital_files.append(os.path.join(root, f))

    vital_files.sort()
    print(f"Sweeping {len(vital_files)} .vital files...")

    all_rows: List[Dict[str, Any]] = []
    file_summaries: List[Dict[str, Any]] = []
    fieldnames = [
        "language", "file", "category", "final status", "stage",
        "severity", "rule code", "line:col", "message",
        "flagged text", "codepoints (U+XXXX) of flagged chars", "full original line"
    ]

    for idx, vf in enumerate(vital_files, start=1):
        rel = os.path.relpath(vf, PROJECT_ROOT).replace("\\", "/")
        print(f"[{idx:02d}/{len(vital_files):02d}] Sweeping {rel}...")
        rows = sweep_file(vf, demo_catalog)
        all_rows.extend(rows)

        # File-level summary
        f_lang = rows[0]["language"]
        f_cat = rows[0]["category"]
        f_status = rows[0]["final status"]
        real_findings = [r for r in rows if r["severity"] != "CLEAN"]
        f_findings_count = len(real_findings)

        # Determine first failing stage
        first_fail = "NONE"
        for r in rows:
            sev = r.get("severity", "").upper()
            if sev in ("FAILED", "BLOCKED", "ERROR", "CRITICAL"):
                stg = r.get("stage", "")
                if stg not in ("NONE", "code_health_errors", "code_health_dead_code"):
                    first_fail = stg
                    break
        if first_fail == "NONE" and f_findings_count > 0:
            first_fail = real_findings[0].get("stage", "NONE")

        file_summaries.append({
            "language": f_lang,
            "file": rel,
            "category": f_cat,
            "final status": f_status,
            "findings": f_findings_count,
            "first failing stage": first_fail
        })

    # Print summary table
    print("\n" + "=" * 110)
    print("VITAL DEMO SWEEP SUMMARY TABLE")
    print("=" * 110)
    summary_headers = ["language", "file", "category", "final status", "findings", "first failing stage"]
    print(f"{'Language':<12} | {'File':<55} | {'Category':<15} | {'Final Status':<20} | {'Findings':<8} | {'First Failing Stage'}")
    print("-" * 140)
    for fs in file_summaries:
        print(f"{fs['language']:<12} | {fs['file']:<55} | {fs['category']:<15} | {fs['final status']:<20} | {fs['findings']:<8} | {fs['first failing stage']}")
    print("=" * 110 + "\n")

    # Write CSV
    os.makedirs(os.path.dirname(args.csv_out), exist_ok=True)
    with open(args.csv_out, "w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)
    print(f"Saved CSV to: {args.csv_out} ({len(all_rows)} total rows)")

    # Write Markdown
    os.makedirs(os.path.dirname(args.md_out), exist_ok=True)
    with open(args.md_out, "w", encoding="utf-8") as fp:
        fp.write("# VITAL Multi-Stage Compiler & Code Health Audit Sweep\n\n")
        fp.write(f"- Total Files Audited: {len(vital_files)}\n")
        fp.write(f"- Total Rows / Findings: {len(all_rows)}\n\n")

        fp.write("## File Summaries\n\n")
        fp.write("| " + " | ".join(summary_headers) + " |\n")
        fp.write("| " + " | ".join(["---"] * len(summary_headers)) + " |\n")
        for fs in file_summaries:
            cells = [str(fs.get(h, "")).replace("|", "\\|") for h in summary_headers]
            fp.write("| " + " | ".join(cells) + " |\n")
        fp.write("\n\n## Detailed Findings\n\n")
        fp.write("| " + " | ".join(fieldnames) + " |\n")
        fp.write("| " + " | ".join(["---"] * len(fieldnames)) + " |\n")
        for r in all_rows:
            # Escape pipe characters for markdown table
            cells = [str(r.get(f, "")).replace("|", "\\|").replace("\n", " ") for f in fieldnames]
            fp.write("| " + " | ".join(cells) + " |\n")
    print(f"Saved Markdown table to: {args.md_out}")


if __name__ == "__main__":
    main()
