import os
import sys
sys.path.insert(0, os.path.abspath("."))
from web.security_analyzer import DeterministicSecurityScanner

path = 'examples/hindi/bank_ledger_system.vital'
with open(path, encoding='utf-8') as f:
    code = f.read()

findings = DeterministicSecurityScanner.scan_lexical(code, include_homoglyphs=True)
print(f"Direct scan_lexical findings count: {len(findings)}")
for f in findings:
    print(f"Line {f.line}:{f.column} - {f.title}")
