import os, sys
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import web.demo_manager as dm
from web.code_health import analyze_health
import web.pipeline_tracker as pt

all_demos = dm.get_all_demos()['demos']
clean_demos = [d for d in all_demos if not d['path'].startswith('examples/security_lab/')]

print(f"Total clean demos: {len(clean_demos)}")

for d in clean_demos:
    p = d['path']
    with open(p, 'r', encoding='utf-8') as f:
        src = f.read()
    h = analyze_health(src, d['language'])
    dead_items = h.get('dead_code_details', [])
    sec_findings = h.get('security', {}).get('findings', [])
    err_count = len(h.get('errors', []))
    tracker = pt.execute_pipeline_with_tracker(src, d['language'], 'clean_check')
    
    stage_findings = {}
    for st_id, st_data in tracker.stages.items():
        fc = st_data.get('findings_count', 0)
        details = st_data.get('details', {})
        wc = len(details.get('warnings', [])) if isinstance(details, dict) else 0
        fc_list = len(details.get('findings', [])) if isinstance(details, dict) and isinstance(details.get('findings'), list) else 0
        total_f = max(fc, fc_list)
        if total_f > 0 or wc > 0:
            stage_findings[st_id] = (total_f, wc)
            
    if dead_items or sec_findings or err_count > 0 or stage_findings or tracker.status != 'COMPLETED':
        print(f"ISSUE in {p}: dead={len(dead_items)}, sec={len(sec_findings)}, errs={err_count}, stages={stage_findings}, status={tracker.status}")

print("Done scanning.")
