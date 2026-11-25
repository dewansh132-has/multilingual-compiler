# -*- coding: utf-8 -*-
import os
import sys
import json

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)
sys.path.insert(0, os.path.join(repo_root, "src"))

# Load .env
env_file = os.path.join(repo_root, ".env")
if os.path.isfile(env_file):
    with open(env_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ[k.strip()] = v.strip().strip("'\"")

from web.pipeline_tracker import PipelineRunTracker, execute_pipeline_with_tracker, STAGE_ORDER

def test_file(rel_path, lang):
    print(f"\n=======================================================")
    print(f"Testing file: {rel_path} ({lang})")
    print(f"=======================================================")
    with open(os.path.join(repo_root, rel_path), "r", encoding="utf-8") as f:
        code = f.read()

    tracker = PipelineRunTracker(run_id=f"test-s12-{os.path.basename(rel_path)}")
    execute_pipeline_with_tracker(
        source_code=code,
        language_hint=lang,
        tracker=tracker,
        run_ai_security=True,
        pause_on_error=True
    )

    print("Pipeline final status:", tracker.final_status)
    print("Completed stages count:", tracker.completed_stages_count)
    s12 = tracker.stages.get("ai_security_analysis", {})
    print("Stage 12 status:", s12.get("status"))
    print("Stage 12 summary:", s12.get("summary"))
    print("Stage 12 reason:", s12.get("reason"))
    print("Stage 12 details:", json.dumps(s12.get("details", {}), indent=2))

    s13 = tracker.stages.get("sandbox_execution", {})
    print("Stage 13 status:", s13.get("status"))
    s14 = tracker.stages.get("final_report", {})
    print("Stage 14 status:", s14.get("status"))

    output = tracker.artifacts.get("output", "")
    print(f"Output length: {len(output)}")
    print(f"Output first 100 chars: {output[:100]}")

test_file("examples/telugu/task_scheduler_engine.vital", "telugu")
test_file("examples/security_lab/hindi/sec_auth_account_hi.vital", "hindi")
