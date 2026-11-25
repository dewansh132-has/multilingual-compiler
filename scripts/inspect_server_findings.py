import urllib.request
import json

resp = urllib.request.urlopen('http://127.0.0.1:8000/api/demo-content?path=examples/hindi/bank_ledger_system.vital')
content = json.loads(resp.read().decode('utf-8'))

req = urllib.request.Request(
    'http://127.0.0.1:8000/api/health/analyze',
    data=json.dumps({'source': content['code'], 'language': 'Hindi', 'path': 'examples/hindi/bank_ledger_system.vital'}).encode('utf-8'),
    headers={'Content-Type': 'application/json'}
)
resp = urllib.request.urlopen(req)
data = json.loads(resp.read().decode('utf-8'))
findings = data.get('security', {}).get('findings', [])
print(f"Total findings: {len(findings)}")
for i, f in enumerate(findings):
    print(f"{i+1}. id={f.get('id')} rule={f.get('rule_id')} line={f.get('line')} msg={f.get('message')}")
