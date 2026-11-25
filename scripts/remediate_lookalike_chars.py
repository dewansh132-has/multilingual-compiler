import glob, os, re, sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

PROHIBITED_MAP = {
    '\u0964': '.',      # Devanagari danda ।
    '\u0965': '.',      # Devanagari double danda ॥
    '\u0903': ':',      # Devanagari visarga ः
    '\u0983': ':',      # Bengali visarga ঃ
    '\u0C03': ':',      # Telugu visarga ః
    '\u2018': "'",      # left single quote
    '\u2019': "'",      # right single quote
    '\u201C': '"',      # left double quote
    '\u201D': '"',      # right double quote
    '\u00A0': ' ',      # non-breaking space
    '\u200B': '',       # zero-width space
    '\u200C': '',       # zero-width non-joiner
    '\u200D': '',       # zero-width joiner
}

# Devanagari digits
for i in range(10):
    PROHIBITED_MAP[chr(0x0966 + i)] = str(i)
# Bengali digits
for i in range(10):
    PROHIBITED_MAP[chr(0x09E6 + i)] = str(i)
# Telugu digits
for i in range(10):
    PROHIBITED_MAP[chr(0x0C66 + i)] = str(i)

files = glob.glob(os.path.join(PROJECT_ROOT, 'examples', '*', '*.vital'))
files = [f for f in files if 'security_lab' not in f.replace('\\', '/') and 'saved' not in f.replace('\\', '/')]

changes_log = []
changed_files = []

for fpath in sorted(files):
    norm_path = os.path.relpath(fpath, PROJECT_ROOT).replace('\\', '/')
    with open(fpath, 'r', encoding='utf-8') as f:
        original = f.read()
    
    modified = original
    file_changes = []
    
    for char, repl in PROHIBITED_MAP.items():
        if char in modified:
            count = modified.count(char)
            # Find lines
            for l_no, line in enumerate(modified.splitlines(), start=1):
                if char in line:
                    file_changes.append({
                        'file': norm_path,
                        'line': l_no,
                        'char': char,
                        'codepoint': f"U+{ord(char):04X}",
                        'replacement': repl,
                        'old_line': line
                    })
            modified = modified.replace(char, repl)
            
    if modified != original:
        with open(fpath, 'w', encoding='utf-8', newline='\n') as f:
            f.write(modified)
        changed_files.append(norm_path)
        changes_log.extend(file_changes)
        print(f"Updated {norm_path}: {len(file_changes)} replacements.")

print(f"\nTotal files updated: {len(changed_files)}")
print(f"Total replacements made: {len(changes_log)}")
