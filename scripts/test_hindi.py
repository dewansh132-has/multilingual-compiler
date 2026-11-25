import os
import sys
sys.path.insert(0, os.path.abspath("."))
from web.security_analyzer import DeterministicSecurityScanner, security_coordinator
from web.code_health import analyze_health
from web.pipeline_tracker import PipelineRunTracker, execute_pipeline_with_tracker

path = 'examples/hindi/bank_ledger_system.vital'
with open(path, encoding='utf-8') as f:
    code = f.read()

print("File size:", len(code), "lines:", len(code.splitlines()))

# 1. Lexical scan directly
lex_findings = DeterministicSecurityScanner.scan_lexical(code, include_homoglyphs=True)
print(f"\n--- scan_lexical(include_homoglyphs=True): {len(lex_findings)} findings ---")
for f in lex_findings:
    print(f"  rule={f.rule_id} title={f.title} line={f.line} col={f.column} evidence={f.evidence}")

# 2. Code Health
h = analyze_health(code, language='Hindi', filename='bank_ledger_system.vital')
print(f"\n--- Code Health: errors={len(h.get('errors', []))}, sec={len(h.get('security', {}).get('findings', []))}, dead={len(h.get('dead_code', {}).get('items', []))} ---")
for f in h.get('security', {}).get('findings', []):
    print(f"  rule={f['rule_id']} msg={f['message']} line={f['line']}")

# 3. Pipeline run
tracker = PipelineRunTracker(run_id='test_hi', source_revision=1, source_hash='hash', session_id='test')
execute_pipeline_with_tracker(
    source_code=code,
    language_hint='Hindi',
    run_ai_security=False,
    tracker=tracker,
    pause_on_error=False,
    resume_from=None,
    source_revision=1,
    security_override=False,
    session_id='test'
)
d = tracker.to_dict()
print(f"\n--- Pipeline Overall: {d.get('overall_status')} ---")
for s in d.get('stages', []):
    findings = s.get('details', {}).get('findings', [])
    print(f"  Stage {s['id']}: status={s['status']} findings={len(findings)}")
