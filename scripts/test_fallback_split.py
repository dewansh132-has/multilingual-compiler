import os
import sys
import re

path = 'examples/hindi/bank_ledger_system.vital'
with open(path, encoding='utf-8') as f:
    code = f.read()

lines = code.splitlines()
code_tokens = []
pattern = r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\r\n]*)'
for l_no, line_str in enumerate(lines, start=1):
    parts = re.split(pattern, line_str)
    cur_col = 1
    for idx, part in enumerate(parts):
        if idx % 2 == 0 and part:
            code_tokens.append((part, l_no, cur_col))
        cur_col += len(part)

HOMOGLYPH_DEVANAGARI = {
    'ः': ':',   # Visarga pretending to be colon
    '।': '|',   # Danda pretending to be pipe
    '०': '0',   # Zero pretending to be 'o'
    'ऽ': 'S'    # Avagraha pretending to be 'S'
}

matches = []
for tok_lex, tok_line, tok_col in code_tokens:
    for dev_char, sym_char in HOMOGLYPH_DEVANAGARI.items():
        if dev_char in tok_lex:
            matches.append((tok_line, tok_col + tok_lex.find(dev_char), dev_char, tok_lex))

print(f"Fallback split matches: {len(matches)}")
for m in matches:
    print(m)
