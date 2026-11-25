import os
import sys
sys.path.insert(0, os.path.abspath("."))
from web.code_health import analyze_health

files = [
    ("Telugu sec_injection_eval_te.vital", "examples/security_lab/telugu/sec_injection_eval_te.vital", "Telugu"),
    ("Nepali weather_station_analytics.vital", "examples/nepali/weather_station_analytics.vital", "Nepali")
]

for label, fpath, lang in files:
    print(f"\n=======================================================")
    print(f"FILE: {label} ({fpath})")
    print(f"=======================================================")
    with open(fpath, encoding="utf-8") as f:
        src = f.read()

    lines = src.splitlines()
    h = analyze_health(src, language=lang, filename=os.path.basename(fpath))
    dc = h.get("dead_code", {})
    pct = dc.get("percentage")
    items = dc.get("items", [])
    metrics = h.get("metrics", {})
    code_lines_count = metrics.get("code_lines", 0)

    print(f"Total lines: {metrics.get('total_lines')}")
    print(f"Code lines count (denominator): {code_lines_count}")
    print(f"Code Health Dead Code %: {pct}")
    print(f"Dead Code items count: {len(items)}")

    dead_lines_set = set()
    print("\nAll Dead Code Items:")
    for it in items:
        lno = it["line"]
        dead_lines_set.add(lno)
        line_text = lines[lno - 1] if 1 <= lno <= len(lines) else ""
        print(f"  Line {lno:3d} [{it['kind']:16s}]: {it['message']}")
        print(f"           Source: {line_text.strip()}")

    print(f"\nNumerator (unique dead lines count): {len(dead_lines_set)}")
    print(f"Formula: ({len(dead_lines_set)} / {code_lines_count}) * 100 = {(len(dead_lines_set) / max(1, code_lines_count)) * 100:.4f}% -> round(..., 1) = {round((len(dead_lines_set) / max(1, code_lines_count)) * 100, 1)}%")
