import os
import sys
sys.path.insert(0, os.path.abspath("."))
import hashlib
from web.pipeline_tracker import PipelineRunTracker, execute_pipeline_with_tracker

with open('examples/security_lab/telugu/sec_injection_eval_te.vital', encoding='utf-8') as f:
    code = f.read()

code_hash = hashlib.sha256(code.encode('utf-8')).hexdigest()
tracker = PipelineRunTracker(run_id='test_run', source_revision=1, source_hash=code_hash, session_id='test')
execute_pipeline_with_tracker(
    source_code=code,
    language_hint='Telugu',
    run_ai_security=False,
    tracker=tracker,
    pause_on_error=True,
    resume_from=None,
    source_revision=1,
    security_override=False,
    session_id='test'
)

d = tracker.to_dict()
print('Pipeline status:', d.get('overall_status'))
for s in d.get('stages', []):
    findings = s.get('details', {}).get('findings', [])
    print(f"Stage {s['id']}: status={s['status']} findings={len(findings)}")
