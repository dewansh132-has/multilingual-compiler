import os
import sys

path = 'examples/hindi/bank_ledger_system.vital'
with open(path, encoding='utf-8') as f:
    code = f.read()

chars_to_check = {
    'ः': 'U+0903 Devanagari Visarga',
    '।': 'U+0964 Devanagari Danda',
    '॥': 'U+0965 Devanagari Double Danda',
    '०': 'U+0966 Devanagari Digit Zero',
    'ऽ': 'U+093D Devanagari Avagraha',
    '\u00A0': 'U+00A0 NBSP',
    '\u200B': 'U+200B ZWSP',
    '\u200C': 'U+200C ZWNJ',
    '\u200D': 'U+200D ZWJ',
}

found = []
lines = code.splitlines()
for line_no, line in enumerate(lines, start=1):
    for col_no, ch in enumerate(line, start=1):
        if ch in chars_to_check:
            # determine surrounding context
            start_idx = max(0, col_no - 15)
            end_idx = min(len(line), col_no + 15)
            surrounding = line[start_idx:end_idx]
            found.append({
                "line": line_no,
                "col": col_no,
                "char": ch,
                "name": chars_to_check[ch],
                "codepoint": f"U+{ord(ch):04X}",
                "surrounding": surrounding,
                "line_text": line
            })

print(f"Total homoglyph / special chars found in bank_ledger_system.vital: {len(found)}")
for item in found:
    print(f"Line {item['line']}:{item['col']} | {item['codepoint']} ({item['name']}) | Context: {repr(item['surrounding'])}")
