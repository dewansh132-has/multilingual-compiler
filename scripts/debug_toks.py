import os
import sys
sys.path.insert(0, os.path.abspath("."))
from web.security_analyzer import _repair_tokens

path = 'examples/hindi/bank_ledger_system.vital'
with open(path, encoding='utf-8') as f:
    code = f.read()

toks = _repair_tokens(code)
print(f"toks count: {len(toks)}")
