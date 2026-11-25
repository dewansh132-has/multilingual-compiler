# -*- coding: utf-8 -*-
import os
import glob
import sys

sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath("src"))

from web.pipeline_tracker import execute_pipeline_with_tracker, PipelineRunTracker, STAGE_ORDER

def evaluate_demo(filepath):
    code = open(filepath, encoding="utf-8").read()
    filename = os.path.basename(filepath)
    rel_path = os.path.relpath(filepath, "examples")
    parts = rel_path.split(os.sep)
    category = parts[0]
    lang = parts[1] if len(parts) > 1 else "english"

    tracker = PipelineRunTracker("sweep_run", 1, "code_hash", "sweep_session")
    execute_pipeline_with_tracker(
        source_code=code,
        language_hint=lang,
        run_ai_security=False,
        tracker=tracker,
        pause_on_error=True,
        pacing_ms=0.0
    )

    # Determine first failing / blocked stage
    first_fail_stage = 14
    fail_stage_name = ""
    issues = []
    
    for idx, sid in enumerate(STAGE_ORDER, start=1):
        st = tracker.stages.get(sid, {})
        status = st.get("status")
        if status in ("failed", "warning"):
            if idx <= 10:
                first_fail_stage = idx
                fail_stage_name = sid
                issues.append(f"{st.get('summary')}")
                break
            elif idx == 11 and status == "failed":
                first_fail_stage = 11
                fail_stage_name = sid
                issues.append(f"{st.get('summary')}")
                break
        elif status == "blocked":
            first_fail_stage = idx
            fail_stage_name = sid
            issues.append(f"Blocked: {st.get('skip_reason', '')}")
            break

    return category, lang, filename, first_fail_stage, fail_stage_name, issues, tracker

def main():
    files = sorted(glob.glob("examples/**/*.vital", recursive=True))
    print(f"Total .vital files found: {len(files)}")
    print("=" * 120)
    print(f"{'Category':<15} | {'Lang':<10} | {'File':<35} | {'First Fail':<10} | {'Issues'}")
    print("=" * 120)
    
    anomalies = []
    clean_count = 0
    sec_lab_count = 0
    
    for f in files:
        cat, lang, fname, fail_stage, sname, issues, tracker = evaluate_demo(f)
        iss_str = (issues[0][:50] if issues else "")
        status_disp = f"Stage {fail_stage}" if fail_stage < 14 else "Passed (14)"
        print(f"{cat:<15} | {lang:<10} | {fname:<35} | {status_disp:<10} | {iss_str}")
        
        # Verify contracts:
        if "sec_auth_account" in fname or "sec_auth_override" in fname:
            sec_lab_count += 1
            if fail_stage != 5:
                anomalies.append((fname, f"Demo A expected Stage 5, got Stage {fail_stage} ({iss_str})"))
        elif "sec_data_config" in fname or "sec_crypto_failure" in fname:
            sec_lab_count += 1
            if fail_stage != 11:
                anomalies.append((fname, f"Demo B expected Stage 11, got Stage {fail_stage} ({iss_str})"))
        elif "sec_injection_eval" in fname:
            sec_lab_count += 1
            if fail_stage != 11:
                anomalies.append((fname, f"Demo C expected Stage 11, got Stage {fail_stage} ({iss_str})"))
        elif "sec_business_workflow" in fname or "sec_taint_leak" in fname:
            sec_lab_count += 1
            if fail_stage != 3:
                anomalies.append((fname, f"Demo D expected Stage 3, got Stage {fail_stage} ({iss_str})"))
        else:
            clean_count += 1
            if fail_stage != 14:
                anomalies.append((fname, f"Clean demo expected Stage 14, got Stage {fail_stage} ({iss_str})"))

    print("=" * 120)
    print(f"Summary: Clean demos: {clean_count}, Security Lab demos: {sec_lab_count}")
    print(f"Total anomalies against contract: {len(anomalies)}")
    for a in anomalies:
        print(f"  * {a[0]}: {a[1]}")

if __name__ == "__main__":
    main()
