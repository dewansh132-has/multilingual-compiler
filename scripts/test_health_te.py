import os
import sys
sys.path.insert(0, os.path.abspath("."))
from web.code_health import analyze_health, collect_fixable_issues

with open('examples/security_lab/telugu/sec_injection_eval_te.vital', encoding='utf-8') as f:
    code = f.read()

health = analyze_health(code, language='Telugu', filename='sec_injection_eval_te.vital')
fixable = health.get("fixable_issues", [])
print(f"fixable_count from health: {health.get('fixable_count')}")
print(f"len(fixable): {len(fixable)}")
print(f"errors: {len(health.get('errors', []))}")
print(f"security findings: {len(health.get('security', {}).get('findings', []))}")
print(f"dead_code items: {len(health.get('dead_code', {}).get('items', []))}")
print(f"dead_code percentage: {health.get('dead_code', {}).get('percentage')}")
print(f"insecure_percentage: {health.get('security', {}).get('insecure_percentage')}")

print("\n--- All fixable items ---")
for i, item in enumerate(fixable):
    print(f"{i+1}. id={item.get('id')} kind={item.get('kind')} stage={item.get('stage')} line={item.get('line')} msg={item.get('message')}")
