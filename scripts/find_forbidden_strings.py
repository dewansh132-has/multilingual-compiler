import os

forbidden = [
    "Manual Fix Required",
    "No Auto-Fix Available",
    "[manual review]",
    "No validated correction generated",
    "GITHUB-STYLE BATCH REMEDIATION"
]

matches = []
for root, dirs, files in os.walk("."):
    if any(p in root for p in [".git", "__pycache__", "venv", ".cache", "node_modules"]):
        continue
    for f in files:
        if f.endswith((".py", ".js", ".html", ".css", ".md")):
            p = os.path.join(root, f)
            try:
                with open(p, "r", encoding="utf-8") as fp:
                    lines = fp.readlines()
                for idx, line in enumerate(lines, 1):
                    for s in forbidden:
                        if s.lower() in line.lower():
                            matches.append((p, idx, s, line.strip()))
            except Exception:
                pass

print(f"Total forbidden string occurrences: {len(matches)}")
for p, idx, s, line in matches:
    print(f"{p}:{idx} [{s}] -> {line[:80]}")
