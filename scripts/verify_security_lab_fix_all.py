import os
import sys
import glob
import json
from typing import Dict, Any, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.issue_collector import collect_issues
from web.fix_orchestrator import run_stage_targeted_fix_all
from web.pipeline_tracker import execute_pipeline_with_tracker

LANGUAGES = ["english", "hindi", "telugu", "bengali", "marathi", "nepali", "fusion"]

def test_security_lab_remediation(use_ai: bool = False) -> List[Dict[str, Any]]:
    results = []
    
    for lang in LANGUAGES:
        pattern = os.path.join("examples", "security_lab", lang, "*.vital")
        files = sorted(glob.glob(pattern))
        for fpath in files:
            fname = os.path.basename(fpath)
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                orig_code = f.read()
            
            # Baseline issues
            issues_before = collect_issues(orig_code, lang)
            n_before = len(issues_before)
            
            # Run Fix All
            fix_res = run_stage_targeted_fix_all(
                source_code=orig_code,
                language=lang,
                file_path=fpath,
                use_ai=use_ai
            )
            
            applied = fix_res.get("applied_fixes", [])
            n_resolved = fix_res.get("resolved_count", len(applied))
            proposed_code = fix_res.get("proposed_source", orig_code)
            fixer_used = fix_res.get("fixer_source") or ("Deterministic" if not use_ai else "Gemini")
            
            # Re-run pipeline on fixed code
            re_tracker = execute_pipeline_with_tracker(proposed_code, lang, pause_on_error=True)
            final_status = getattr(re_tracker, "final_status", "")
            if not final_status and re_tracker.is_finished:
                final_status = "completed"
            
            # Check baseline output vs new output
            # For security lab files, original halted with no output
            base_out = ""
            new_out = re_tracker.artifacts.get("output", "") if re_tracker.artifacts else ""
            output_changed = (new_out.strip() != base_out.strip()) if base_out.strip() else (bool(new_out.strip()))
            
            rec = {
                "file": fpath,
                "language": lang,
                "issues_before": n_before,
                "issues_resolved": n_resolved,
                "final_status": final_status,
                "fixer_used": fixer_used,
                "output_changed": output_changed,
                "stdout_preview": new_out.strip()[:100].replace("\n", " ")
            }
            results.append(rec)
            print(f"[{lang:7s}] {fname:35s} | Before: {n_before:2d} | Resolved: {n_resolved:2d} | Status: {final_status:10s} | Fixer: {fixer_used} | Output: {'YES' if output_changed else 'NO'}", flush=True)

    return results

if __name__ == "__main__":
    print("=== RUNNING OFFLINE DETERMINISTIC FIX VERIFICATION (use_ai=False) ===")
    res_offline = test_security_lab_remediation(use_ai=False)
    with open("reports/security_lab_offline_fix_report.json", "w", encoding="utf-8") as rf:
        json.dump(res_offline, rf, indent=2)
    print("Done. Saved reports/security_lab_offline_fix_report.json")
