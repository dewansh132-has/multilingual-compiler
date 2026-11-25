#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
scripts/verify_security_lab.py — Verification across the entire VITAL Security Lab (Task E)

For every program in examples/security_lab (all 6 languages, 24 programs) through real HTTP endpoints:
  1. POST /api/pipeline/run (before Fix All): verify stages 1-10 and count security findings.
  2. POST /api/ai/fix-all: generate validated fixpoint patches.
  3. POST /api/ai/apply-fix: atomically persist and verify working copy.
  4. POST /api/pipeline/run (after Fix All): verify stages 1-10 and count security findings.
  5. Print structured summary table and metric report.
"""

import os
import sys
import glob
import time
from typing import Dict, Any, List

# Ensure VITAL_AI_DISABLED=1
os.environ["VITAL_AI_DISABLED"] = "1"

# Force UTF-8 stdout on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from web.server import app
from web.working_source_manager import working_source_manager


def detect_file_language(path: str) -> str:
    path_lower = path.lower().replace("\\", "/")
    if "/hindi/" in path_lower or "_hi.vital" in path_lower:
        return "Hindi"
    if "/telugu/" in path_lower or "_te.vital" in path_lower:
        return "Telugu"
    if "/bengali/" in path_lower or "_bn.vital" in path_lower:
        return "Bengali"
    if "/marathi/" in path_lower or "_mr.vital" in path_lower:
        return "Marathi"
    if "/nepali/" in path_lower or "_ne.vital" in path_lower:
        return "Nepali"
    return "English"


def main():
    search_pattern = os.path.join(PROJECT_ROOT, "examples", "security_lab", "*", "*.vital")
    files = sorted(glob.glob(search_pattern))

    if not files:
        print(f"Error: No .vital files found matching {search_pattern}")
        sys.exit(1)

    print("=" * 115)
    print("VITAL SECURITY LAB VERIFICATION REPORT (HTTP ENDPOINTS, VITAL_AI_DISABLED=1)")
    print("=" * 115)
    header = f"{'File':<30} | {'Lang':<8} | {'Stage 5':<8} | {'Stages 1-10 (B/A)':<18} | {'Findings':<10} | {'App':<4} | {'Rej':<4} | {'Man':<4} | {'Time (s)':<8}"
    print(header)
    print("-" * 115)

    client = app.test_client()
    working_source_manager.clear_all_working_copies()

    total_programs = len(files)
    green_before = 0
    green_after = 0
    failures: List[Dict[str, Any]] = []

    for file_path in files:
        rel_name = os.path.relpath(file_path, PROJECT_ROOT).replace("\\", "/")
        fname = os.path.basename(file_path)
        lang = detect_file_language(file_path)

        with open(file_path, "r", encoding="utf-8") as f:
            code_before = f.read()

        t0 = time.time()

        # Step 1: POST /api/pipeline/run (before Fix All)
        resp_before = client.post("/api/pipeline/run", json={
            "code": code_before,
            "language": lang,
            "use_ai_security": False,
            "source_revision": 1
        })
        data_before = resp_before.get_json() or {}
        stages_before = data_before.get("stages", [])
        s10_before_ok = all(s.get("status") in ("completed", "warning", "passed") for s in stages_before[:10])
        if s10_before_ok:
            green_before += 1
        first_fail_b = next((s["id"] for s in stages_before[:10] if s.get("status") not in ("completed", "warning", "passed")), None)
        s10_b_str = "GREEN" if s10_before_ok else f"FAIL({first_fail_b[:7] if first_fail_b else 'ERR'})"

        sec_stage_before = next((s for s in stages_before if s["id"] == "security_analysis"), None)
        findings_before = sec_stage_before.get("details", {}).get("findings", []) if sec_stage_before else []
        if not findings_before:
            scans_init = DeterministicSecurityScanner.scan_multilingual_security(code_before, lang)
            findings_before = [s.to_dict() if hasattr(s, "to_dict") else s for s in scans_init]
        f_before_count = len(findings_before)

        # Step 2: POST /api/ai/fix-all
        resp_fix = client.post("/api/ai/fix-all", json={
            "stage_id": "security_analysis",
            "source_code": code_before,
            "language": lang,
            "file_path": file_path,
            "source_revision": 1,
            "use_ai": False,
            "diagnostics": findings_before
        })
        fix_data = resp_fix.get_json() or {}
        app_count = len(fix_data.get("applied_fixes", []))
        rej_count = len(fix_data.get("rejected_fixes", []))
        man_count = len(fix_data.get("manual_fixes", []))
        proposed_code = fix_data.get("proposed_source", code_before)

        # Step 3: POST /api/ai/apply-fix
        if proposed_code != code_before:
            client.post("/api/ai/apply-fix", json={
                "file_path": file_path,
                "code": proposed_code,
                "source_revision": 1,
                "stage_id": "security_analysis",
                "language": lang
            })

        # Step 4: POST /api/pipeline/run (after Fix All)
        resp_after = client.post("/api/pipeline/run", json={
            "code": proposed_code,
            "language": lang,
            "use_ai_security": False,
            "source_revision": 2
        })
        data_after = resp_after.get_json() or {}
        elapsed = time.time() - t0

        stages_after = data_after.get("stages", [])
        s10_after_ok = all(s.get("status") in ("completed", "warning", "passed") for s in stages_after[:10])
        first_fail_a = next((s["id"] for s in stages_after[:10] if s.get("status") not in ("completed", "warning", "passed")), None)
        if s10_after_ok:
            green_after += 1
        else:
            failures.append({
                "file": fname,
                "language": lang,
                "stage": first_fail_a,
                "errors": [s.get("summary", "") for s in stages_after if s.get("id") == first_fail_a]
            })
        s10_a_str = "GREEN" if s10_after_ok else f"FAIL({first_fail_a[:7] if first_fail_a else 'ERR'})"

        st5_b = next((s.get("status") for s in stages_before if s.get("id") == "semantic_analysis"), "unknown")
        st5_a = next((s.get("status") for s in stages_after if s.get("id") == "semantic_analysis"), "unknown")
        st5_str = "PASS" if (st5_b in ("completed", "passed") and st5_a in ("completed", "passed")) else f"{st5_b[:4]}"

        sec_stage_after = next((s for s in stages_after if s["id"] == "security_analysis"), None)
        findings_after = sec_stage_after.get("details", {}).get("findings", []) if sec_stage_after else []
        f_after_count = len(findings_after)

        stages_ba = f"{s10_b_str} -> {s10_a_str}"
        findings_ba = f"{f_before_count} -> {f_after_count}"

        print(f"{fname:<30} | {lang:<8} | {st5_str:<8} | {stages_ba:<18} | {findings_ba:<10} | {app_count:<4} | {rej_count:<4} | {man_count:<4} | {elapsed:<8.2f}")

    working_source_manager.clear_all_working_copies()

    print("=" * 115)
    print(f"SUMMARY: Total Programs: {total_programs}")
    print(f"  • Stages 1-10 GREEN Before Fix All: {green_before} / {total_programs} ({green_before*100/total_programs:.1f}%)")
    print(f"  • Stages 1-10 GREEN After Fix All:  {green_after} / {total_programs} ({green_after*100/total_programs:.1f}%)")

    if failures:
        print("\nPrograms with Stages 1-10 Failures after Fix All:")
        for fail in failures:
            print(f"  - {fail['file']} ({fail['language']}) in stage '{fail['stage']}':")
            for err in fail["errors"][:3]:
                print(f"      {err}")
    else:
        print("\nALL programs reached Stages 1-10 GREEN after Fix All!")
    print("=" * 105)


if __name__ == "__main__":
    main()
