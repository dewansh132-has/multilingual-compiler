import glob, os, re

PROHIBITED = {
    '\u0964': ('.', 'danda'),
    '\u0965': ('.', 'double danda'),
    '\u0903': (':', 'Devanagari visarga'),
    '\u0983': (':', 'Bengali visarga'),
    '\u0C03': (':', 'Telugu visarga'),
    '\u2018': ("'", 'left single quote'),
    '\u2019': ("'", 'right single quote'),
    '\u201C': ('"', 'left double quote'),
    '\u201D': ('"', 'right double quote'),
    '\u00A0': (' ', 'non-breaking space'),
    '\u200B': ('', 'zero-width space'),
    '\u200C': ('', 'zero-width non-joiner'),
    '\u200D': ('', 'zero-width joiner'),
}

for i in range(10):
    PROHIBITED[chr(0x0966 + i)] = (str(i), f'Devanagari digit {i}')
    PROHIBITED[chr(0x09E6 + i)] = (str(i), f'Bengali digit {i}')
    PROHIBITED[chr(0x0C66 + i)] = (str(i), f'Telugu digit {i}')

files = glob.glob('examples/*/*.vital')
files = [f for f in files if 'security_lab' not in f.replace('\\', '/') and 'saved' not in f.replace('\\', '/')]

print(f"Total clean files checked: {len(files)}")
found_files = {}

for fpath in sorted(files):
    norm_path = fpath.replace('\\', '/')
    with open(fpath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    file_matches = []
    lines = content.splitlines()
    for l_no, line in enumerate(lines, start=1):
        for col_no, ch in enumerate(line, start=1):
            if ch in PROHIBITED:
                repl, name = PROHIBITED[ch]
                file_matches.append({
                    'line': l_no,
                    'col': col_no,
                    'char': ch,
                    'cp': f"U+{ord(ch):04X}",
                    'name': name,
                    'replacement': repl,
                    'line_text': line
                })
    if file_matches:
        found_files[norm_path] = file_matches

print(f"Files with prohibited chars: {len(found_files)}")
for p, matches in found_files.items():
    cps = set(m['cp'] for m in matches)
    print(f"  {p}: {len(matches)} occurrences, codepoints: {cps}")

print("\n" + "=" * 60)
print("DETAILED OCCURRENCES BY FILE")
print("=" * 60)
for p, matches in found_files.items():
    print(f"\n=== {p} ({len(matches)} items) ===")
    for m in matches:
        print(f"  Line {m['line']}:{m['col']} | {m['cp']} ({m['name']}) -> replace with '{m['replacement']}'")
        print(f"    Line: {m['line_text']}")
