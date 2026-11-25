# -*- coding: utf-8 -*-
"""
scripts/check_stage_results.py

Runs ONLY stages 1-10 on every genuine .vital file under examples/
and prints a formatted table:
file | first failing stage | error message
"""

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from web.pipeline_tracker import execute_pipeline_with_tracker, STAGE_ORDER

def check_file(vital_path):
    rel_path = os.path.relpath(vital_path, PROJECT_ROOT)
    with open(vital_path, "r", encoding="utf-8") as f:
        code = f.read()

    tracker = execute_pipeline_with_tracker(
        source_code=code,
        language_hint="",
        run_ai_security=False,
        mandatory_only=True
    )

    first_fail_stage = "PASSED (1-10)"
    first_fail_msg = "-"

    # Check stages 1-10
    for sid in STAGE_ORDER[:10]:
        st = tracker.stages.get(sid, {})
        status = st.get("status")
        if status in ("failed", "blocked"):
            first_fail_stage = sid
            first_fail_msg = st.get("reason") or st.get("summary") or "Error"
            break

    return rel_path, first_fail_stage, first_fail_msg

def main():
    examples_dir = os.path.join(PROJECT_ROOT, "examples")
    vital_files = []
    for root, dirs, files in os.walk(examples_dir):
        # Exclude saved working copies
        if "saved" in root.split(os.sep):
            continue
        for f in sorted(files):
            if f.endswith(".vital"):
                vital_files.append(os.path.join(root, f))

    vital_files.sort()
    print(f"Found {len(vital_files)} .vital files under examples/")
    print(f"{'FILE':<60} | {'FIRST FAILING STAGE':<22} | {'ERROR MESSAGE'}")
    print("-" * 120)

    results = []
    for vf in vital_files:
        rel_path, stage, msg = check_file(vf)
        results.append((rel_path, stage, msg))
        clean_msg = (msg[:60] + "...") if len(msg) > 60 else msg
        print(f"{rel_path:<60} | {stage:<22} | {clean_msg}")

    return results

if __name__ == "__main__":
    main()
