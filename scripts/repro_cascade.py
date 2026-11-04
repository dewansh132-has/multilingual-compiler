# -*- coding: utf-8 -*-
"""
scripts/repro_cascade.py — Reproduction Script for Fix All & Stage Cascade Diagnostics

Demonstrates the exact execution path used by the VITAL IDE UI:
1. Loads an intentionally insecure fixture from examples/security_lab/ (e.g. sec_auth_account.vital).
2. Runs the multi-finding security scan (3+ seeded vulnerabilities).
3. Executes the full 14-stage compilation pipeline before any fixes are applied (pause_on_error=True).
4. Invokes "Fix All" (remediation_engine.generate_fix_all -> remediation_engine.apply_and_verify_fix).
5. Re-executes the compilation pipeline on the patched working copy.
6. Prints a stage x status table comparing before vs. after across English, Hindi, and Telugu.
"""

import sys
import os
import time

# Reconfigure stdout for UTF-8 on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
SRC_DIR = os.path.join(PROJECT_ROOT, 'src')
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from web.security_analyzer import security_coordinator
from web.pipeline_tracker import execute_pipeline_with_tracker, STAGE_DEFINITIONS
from web.ai_remediation_engine import remediation_engine
from web.working_source_manager import working_source_manager


TARGET_DEMOS = [
    {
        "language": "English",
        "path": "examples/security_lab/english/sec_auth_account.vital",
        "desc": "Account & Permission Management (English)"
    },
    {
        "language": "Hindi",
        "path": "examples/security_lab/hindi/sec_auth_account_hi.vital",
        "desc": "Account & Permission Management (Hindi)"
    },
    {
        "language": "Telugu",
        "path": "examples/security_lab/telugu/sec_auth_account_te.vital",
        "desc": "Account & Permission Management (Telugu)"
    }
]


def run_repro_for_demo(demo_info: dict) -> dict:
    lang = demo_info["language"]
    rel_path = demo_info["path"]
    desc = demo_info["desc"]

    print(f"\n{'=' * 80}")
    print(f"  RUNNING CASCADE REPRODUCTION: {lang.upper()} — {desc}")
    print(f"  File: {rel_path}")
    print(f"{'=' * 80}")

    # 1. Clean slate: Reset any previous working copies to pristine fixture
    working_source_manager.restore_original_source(rel_path)

    ok, orig_code, err = working_source_manager.get_original_source(rel_path)
    if not ok:
        print(f"ERROR: Could not read original source for {rel_path}: {err}")
        return {"success": False, "error": err}

    # 2. Multi-finding detection scan (UI equivalent: /api/security/scan)
    scan_start = time.time()
    scan_res = security_coordinator.run_full_scan(
        source_code=orig_code,
        language=lang,
        use_ai_enrichment=False
    )
    scan_ms = (time.time() - scan_start) * 1000.0
    findings = scan_res.get("findings", [])
    print(f"\n[Step 1: Security Scan] Detected {len(findings)} distinct findings ({scan_ms:.1f} ms):")
    for idx, f in enumerate(findings, start=1):
        print(f"  {idx}. [{f.get('id')}] (Line {f.get('line')}, Rule: {f.get('rule_id')}): {f.get('title')}")

    # 3. Initial Pipeline Compilation (UI equivalent: POST /api/pipeline/stream with pause_on_error=True)
    print(f"\n[Step 2: Initial Pipeline Compilation (Before Fix)]")
    t_before = execute_pipeline_with_tracker(
        source_code=orig_code,
        language_hint=lang,
        run_ai_security=False,
        pause_on_error=True,
        source_revision=1
    )
    print(f"  Status: {t_before.final_status.upper()} | Paused Stage: {t_before.paused_stage or 'None'}")

    # 4. Invoke "Fix All" (UI equivalent: POST /api/ai/fix-all)
    print(f"\n[Step 3: Invoking 'Fix All' on {len(findings)} Diagnostics (Target Stage: security_analysis)]")
    fixall_start = time.time()
    fix_res = remediation_engine.generate_fix_all(
        source_code=orig_code,
        stage_id="security_analysis",
        diagnostics=findings,
        language=lang,
        source_revision=1,
        file_path=rel_path,
        use_ai=False  # Deterministic/rule-based fallback ensures reproducible fast benchmarking
    )
    fixall_ms = (time.time() - fixall_start) * 1000.0

    print(f"  Fix All Result: Success = {fix_res.get('success')}")
    print(f"  Resolved Count: {fix_res.get('resolved_count', 0)} / {len(findings)}")
    print(f"  Resolved IDs:   {fix_res.get('resolved_diagnostic_ids', [])}")
    print(f"  Remaining IDs:  {fix_res.get('remaining_diagnostic_ids', [])}")
    print(f"  Remediation Generation Time: {fixall_ms:.1f} ms")

    prop_source = fix_res.get("proposed_source", "")
    diff_str = fix_res.get("diff", "")

    if diff_str:
        print(f"\n  Proposed Patch Diff:")
        diff_lines = diff_str.strip().splitlines()
        for dl in diff_lines[:15]:
            print(f"    {dl}")
        if len(diff_lines) > 15:
            print(f"    ... [{len(diff_lines) - 15} more diff lines]")

    # 5. Apply Fix (UI equivalent: POST /api/ai/apply-fix)
    print(f"\n[Step 4: Applying & Verifying Patch (POST /api/ai/apply-fix)]")
    apply_res = remediation_engine.apply_and_verify_fix(
        file_path=rel_path,
        proposed_source=prop_source or orig_code,
        expected_revision=1,
        stage_id="security_analysis",
        language=lang,
        finding_id="FIX-ALL-BATCH"
    )
    print(f"  Apply Result: Success = {apply_res.get('success')} (Revision: {apply_res.get('source_revision')})")

    # 6. Recompilation on Patched Working Source (UI equivalent: runCompiler(null, true))
    print(f"\n[Step 5: Recompiling Pipeline on Patched Source (After Fix)]")
    t_after = execute_pipeline_with_tracker(
        source_code=prop_source or orig_code,
        language_hint=lang,
        run_ai_security=False,
        pause_on_error=True,
        source_revision=apply_res.get("source_revision", 2)
    )
    print(f"  Status: {t_after.final_status.upper()} | Paused Stage: {t_after.paused_stage or 'None'}")

    # 7. Print Comparative 14-Stage Table
    print(f"\n[Step 6: Comparative Stage Matrix — {lang.upper()}]")
    print("-" * 88)
    print(f"  {'#':2s} | {'Stage ID':22s} | {'Before Fix':12s} | {'After Fix':12s} | {'Transition / Impact'}")
    print("-" * 88)

    stage_rows = []
    for idx, defn in enumerate(STAGE_DEFINITIONS, start=1):
        sid = defn["id"]
        st_before = t_before.stages.get(sid, {}).get("status", "unknown").upper()
        st_after = t_after.stages.get(sid, {}).get("status", "unknown").upper()

        if st_before == st_after:
            trans = f"Unchanged ({st_after})"
        elif st_before in ("FAILED", "BLOCKED") and st_after in ("COMPLETED", "WARNING", "READY"):
            trans = f"Unblocked: {st_before} -> {st_after} (PROGRESSED)"
        elif st_before in ("COMPLETED", "PASSED") and st_after in ("FAILED", "BLOCKED"):
            trans = f"REGRESSION: {st_before} -> {st_after} (RED)"
        else:
            trans = f"{st_before} -> {st_after}"

        print(f"  {idx:2d} | {sid:22s} | {st_before:12s} | {st_after:12s} | {trans}")
        stage_rows.append({
            "idx": idx,
            "id": sid,
            "before": st_before,
            "after": st_after,
            "trans": trans
        })

    print("-" * 88)
    print(f"  PIPELINE OVERALL VERDICT: {t_before.final_status.upper()} -> {t_after.final_status.upper()}")
    print("-" * 88)

    # Clean up working copy so repository state remains pristine
    working_source_manager.restore_original_source(rel_path)

    return {
        "language": lang,
        "file_path": rel_path,
        "findings_count": len(findings),
        "status_before": t_before.final_status,
        "status_after": t_after.final_status,
        "stages": stage_rows
    }


def main():
    print(f"================================================================================")
    print(f"  VITAL IDE FIX-FLOW & CASCADE DIAGNOSTIC REPRODUCTION HARNESS")
    print(f"  Testing English, Hindi, and Telugu Security Lab Programs")
    print(f"================================================================================")

    all_results = []
    for demo in TARGET_DEMOS:
        res = run_repro_for_demo(demo)
        all_results.append(res)

    print(f"\n\n{'#' * 80}")
    print(f"  CROSS-LANGUAGE SUMMARY MATRIX")
    print(f"{'#' * 80}")
    print(f"  Language | Findings | Status Before | Status After  | Stage 14 Final Report State")
    print(f"  ---------+----------+---------------+---------------+------------------------------")
    for r in all_results:
        lang = r.get("language", "?")
        cnt = r.get("findings_count", 0)
        s_bef = r.get("status_before", "?").upper()
        s_aft = r.get("status_after", "?").upper()
        st14 = next((s["after"] for s in r.get("stages", []) if s["id"] == "final_report"), "UNKNOWN")
        print(f"  {lang:8s} | {cnt:8d} | {s_bef:13s} | {s_aft:13s} | {st14}")
    print(f"{'#' * 80}\n")


if __name__ == "__main__":
    main()

