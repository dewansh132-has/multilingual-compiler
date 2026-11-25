import os
import sys
sys.path.insert(0, os.path.abspath("."))
from web.fix_orchestrator import run_stage_targeted_fix_all
from web.code_health import analyze_health

with open('examples/security_lab/telugu/sec_injection_eval_te.vital', encoding='utf-8') as f:
    orig_code = f.read()

# First fix
res1 = run_stage_targeted_fix_all(orig_code, language='Telugu', file_path='examples/security_lab/telugu/sec_injection_eval_te.vital', use_ai=False)
patched_code = res1.get('proposed_source')

print("=== AFTER FIRST FIX APPLIED ===")
h2 = analyze_health(patched_code, language='Telugu', filename='sec_injection_eval_te.vital')
print(f"h2 fixable_count: {h2.get('fixable_count')}")
print(f"h2 errors: {len(h2.get('errors', []))}")
print(f"h2 security findings: {len(h2.get('security', {}).get('findings', []))}")
print(f"h2 dead_code items: {len(h2.get('dead_code', {}).get('items', []))}")
for item in h2.get('fixable_issues', []):
    print(f"  {item['id']}: {item['kind']} line {item['line']} - {item['message']}")

print("\n=== NOW USER CLICKS FIX ALL ISSUES AGAIN ON BUFFER ===")
res2 = run_stage_targeted_fix_all(patched_code, language='Telugu', file_path='examples/security_lab/telugu/sec_injection_eval_te.vital', use_ai=False)
print("res2 total_diagnostics:", res2.get("total_diagnostics"))
print("res2 resolved_count:", res2.get("resolved_count"))
print("res2 remaining_count:", res2.get("remaining_count"))
print("res2 applied_fixes count:", len(res2.get("applied_fixes", [])))
print("res2 manual_fixes count:", len(res2.get("manual_fixes", [])))
print("res2 error_diffs count:", len(res2.get("error_diffs", [])))
print("res2 validation_badge_text:", res2.get("validation_badge_text"))
print("res2 delta_text:", res2.get("delta_text"))
