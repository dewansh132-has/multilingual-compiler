with open("web/pipeline_tracker.py", encoding="utf-8") as f:
    lines = f.readlines()
for i, l in enumerate(lines):
    if "security_analysis" in l and "elif stage_id ==" in l:
        print(f"{i+1}: {l.strip()}")
