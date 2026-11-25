import os
import sys
sys.path.insert(0, os.path.abspath("."))
from web.fix_orchestrator import run_stage_targeted_fix_all

with open('examples/security_lab/telugu/sec_injection_eval_te.vital', encoding='utf-8') as f:
    code = f.read()

res = run_stage_targeted_fix_all(code, language='Telugu', file_path='examples/security_lab/telugu/sec_injection_eval_te.vital', use_ai=False)
print("run_stage_targeted_fix_all result keys:", res.keys())
print("total_diagnostics:", res.get("total_diagnostics"))
print("resolved_count:", res.get("resolved_count"))
print("applied_fixes count:", len(res.get("applied_fixes", [])))
print("fixes count:", len(res.get("fixes", [])))
print("delta_text:", res.get("delta_text"))
for g in res.get("groups", []):
    print(f"Group {g['group']} ({g['stage_id']}): fixes_count={g['fixes_count']}")
