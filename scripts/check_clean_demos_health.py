import glob, os, sys
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from web.code_health import analyze_health
import web.pipeline_tracker as pt

files = glob.glob('examples/*/*.vital')
files = [f.replace('\\', '/') for f in files if 'security_lab' not in f.replace('\\', '/') and 'saved' not in f.replace('\\', '/')]

print(f"Checking {len(files)} files...")
issues_by_file = {}

for fpath in sorted(files):
    lang = fpath.split('/')[1]
    with open(fpath, 'r', encoding='utf-8') as f:
        src = f.read()
    h = analyze_health(src, filename=os.path.basename(fpath))
    dead_items = h.get('metrics', {}).get('dead_code', {}).get('items', [])
    err_items = [i for i in h.get('issues', []) if i.get('severity') in ('error', 'critical')]
    sec_pct = h.get('security', {}).get('insecure_percentage', 0.0)
    health_stat = h.get('status')
    
    # Check stop words used as identifiers
    # Let's inspect src/language_rules.json
    if dead_items or err_items or sec_pct > 0 or health_stat != 'healthy':
        issues_by_file[fpath] = {
            'dead': dead_items,
            'errs': err_items,
            'sec_pct': sec_pct,
            'status': health_stat
        }

print(f"Files with Code Health issues: {len(issues_by_file)}")
for p, iss in issues_by_file.items():
    print(f"  {p}: status={iss['status']}, dead={len(iss['dead'])}, errs={len(iss['errs'])}, sec_pct={iss['sec_pct']}")
    for d in iss['dead']:
        print(f"    Dead item: {d}")
