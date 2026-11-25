# -*- coding: utf-8 -*-
"""
scripts/generate_deliverables_data.py — Compute Deliverables Table & Iteration Logs
"""

import os
import sys
import json

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from web.fix_orchestrator import run_ai_fix_and_rerun_loop
from web.pipeline_tracker import PipelineRunTracker, execute_pipeline_with_tracker

def main():
    demos = [
        # Demo A
        ("Demo A (Auth Account)", "english", "examples/security_lab/english/sec_auth_account.vital"),
        ("Demo A (Auth Account)", "hindi", "examples/security_lab/hindi/sec_auth_account_hi.vital"),
        ("Demo A (Auth Account)", "telugu", "examples/security_lab/telugu/sec_auth_account_te.vital"),
        ("Demo A (Auth Account)", "bengali", "examples/security_lab/bengali/sec_auth_account_bn.vital"),
        ("Demo A (Auth Account)", "marathi", "examples/security_lab/marathi/sec_auth_account_mr.vital"),
        ("Demo A (Auth Account)", "nepali", "examples/security_lab/nepali/sec_auth_account_ne.vital"),
        ("Demo A (Auth Account)", "fusion", "examples/security_lab/fusion/sec_auth_account_fusion.vital"),

        # Demo B
        ("Demo B (Data Config)", "english", "examples/security_lab/english/sec_data_config.vital"),
        ("Demo B (Data Config)", "hindi", "examples/security_lab/hindi/sec_data_config_hi.vital"),
        ("Demo B (Data Config)", "telugu", "examples/security_lab/telugu/sec_data_config_te.vital"),
        ("Demo B (Data Config)", "bengali", "examples/security_lab/bengali/sec_data_config_bn.vital"),
        ("Demo B (Data Config)", "marathi", "examples/security_lab/marathi/sec_data_config_mr.vital"),
        ("Demo B (Data Config)", "nepali", "examples/security_lab/nepali/sec_data_config_ne.vital"),
        ("Demo B (Data Config)", "fusion", "examples/security_lab/fusion/sec_data_config_fusion.vital"),

        # Demo C
        ("Demo C (Injection Eval)", "english", "examples/security_lab/english/sec_injection_eval.vital"),
        ("Demo C (Injection Eval)", "hindi", "examples/security_lab/hindi/sec_injection_eval_hi.vital"),
        ("Demo C (Injection Eval)", "telugu", "examples/security_lab/telugu/sec_injection_eval_te.vital"),
        ("Demo C (Injection Eval)", "bengali", "examples/security_lab/bengali/sec_injection_eval_bn.vital"),
        ("Demo C (Injection Eval)", "marathi", "examples/security_lab/marathi/sec_injection_eval_mr.vital"),
        ("Demo C (Injection Eval)", "nepali", "examples/security_lab/nepali/sec_injection_eval_ne.vital"),
        ("Demo C (Injection Eval)", "fusion", "examples/security_lab/fusion/sec_injection_eval_fusion.vital"),

        # Demo D
        ("Demo D (Business Workflow)", "english", "examples/security_lab/english/sec_business_workflow.vital"),
        ("Demo D (Business Workflow)", "hindi", "examples/security_lab/hindi/sec_business_workflow_hi.vital"),
        ("Demo D (Business Workflow)", "telugu", "examples/security_lab/telugu/sec_business_workflow_te.vital"),
        ("Demo D (Business Workflow)", "bengali", "examples/security_lab/bengali/sec_business_workflow_bn.vital"),
        ("Demo D (Business Workflow)", "marathi", "examples/security_lab/marathi/sec_business_workflow_mr.vital"),
        ("Demo D (Business Workflow)", "nepali", "examples/security_lab/nepali/sec_business_workflow_ne.vital"),
        ("Demo D (Business Workflow)", "fusion", "examples/security_lab/fusion/sec_business_workflow_fusion.vital"),
    ]

    results = []
    iteration_samples = {}

    for demo_type, lang, path in demos:
        with open(path, "r", encoding="utf-8") as f:
            src = f.read()

        # Baseline execution
        base_tracker = PipelineRunTracker("base", 1)
        execute_pipeline_with_tracker(src, lang, False, base_tracker)
        base_out = (base_tracker.artifacts or {}).get("output", "")

        res = run_ai_fix_and_rerun_loop(src, lang, path, use_ai=False)

        # Repaired execution
        rep_tracker = PipelineRunTracker("rep", 2)
        execute_pipeline_with_tracker(res.get("proposed_source", src), lang, False, rep_tracker)
        rep_out = (rep_tracker.artifacts or {}).get("output", "")
        out_changed = "Yes" if (base_out.strip() and rep_out.strip() and base_out.strip() != rep_out.strip()) else "No"

        # Fixer used
        fixers = set()
        for it in res.get("iterations", []):
            fixers.add("Deterministic")
        fixer_str = ", ".join(sorted(fixers)) if fixers else "Deterministic"

        initial_issues = res.get("initial_diagnostics_count", 0)
        resolved = res.get("total_resolved", 0)

        results.append({
            "demo_type": demo_type,
            "filename": os.path.basename(path),
            "language": lang.capitalize(),
            "issues_before": initial_issues,
            "issues_fixed": resolved,
            "final_status": res.get("final_status", "COMPLETED"),
            "fixer": fixer_str,
            "out_changed": out_changed
        })

        # Capture sample logs for 1 demo of each type
        if demo_type.startswith("Demo A") and "Demo A" not in iteration_samples:
            iteration_samples["Demo A"] = {"file": path, "logs": res.get("iteration_logs", [])}
        elif demo_type.startswith("Demo B") and "Demo B" not in iteration_samples:
            iteration_samples["Demo B"] = {"file": path, "logs": res.get("iteration_logs", [])}
        elif demo_type.startswith("Demo C") and "Demo C" not in iteration_samples:
            iteration_samples["Demo C"] = {"file": path, "logs": res.get("iteration_logs", [])}
        elif demo_type.startswith("Demo D") and "Demo D" not in iteration_samples:
            iteration_samples["Demo D"] = {"file": path, "logs": res.get("iteration_logs", [])}

    with open("reports/deliverables_data.json", "w", encoding="utf-8") as f:
        json.dump({"results": results, "samples": iteration_samples}, f, indent=2)

    print("Deliverables data generated successfully.")

if __name__ == "__main__":
    main()
