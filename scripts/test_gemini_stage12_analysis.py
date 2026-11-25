# -*- coding: utf-8 -*-
import os
import sys
import json

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

env_file = os.path.join(repo_root, ".env")
with open(env_file, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ[k.strip()] = v.strip().strip("'\"")

from web.gemini_client import ai_client

def test_stage12_prompt(rel_path, lang):
    print(f"\n=======================================================")
    print(f"Testing Stage 12 prompt on {rel_path} ({lang})")
    print(f"=======================================================")
    with open(os.path.join(repo_root, rel_path), "r", encoding="utf-8") as f:
        source = f.read()

    source_lines = source.splitlines()

    system_prompt = (
        "You are an expert compiler security analyzer for VITAL, an educational multilingual programming language. "
        "Analyze the provided source code, language rules, and known Stage 11 SAST findings. "
        "Identify any ADDITIONAL security vulnerabilities or defects that the static analyzer (Stage 11) missed. "
        "STRICT VALIDATION RULES: "
        "1. 'line' MUST be the exact 1-indexed line number where the issue exists. "
        "2. 'evidence' MUST be an exact, verbatim substring of that line in the source code. Never paraphrase. "
        "3. If the code is clean or has no additional security defects, return an empty list: {\"findings\": []}. "
        "Return ONLY a JSON object matching this schema: "
        "{\"findings\": [{\"id\": \"AI-SEC-001\", \"cwe\": \"CWE-78\", \"severity\": \"HIGH\", \"line\": 10, \"evidence\": \"substr\", \"explanation\": \"...\", \"confidence\": 0.95}]}"
    )

    user_prompt = (
        f"Language: {lang}\n"
        f"Known Stage 11 Findings: []\n\n"
        f"Source Code:\n{source[:3000]}\n\n"
        "Analyze for additional security vulnerabilities. Return JSON only."
    )

    res = ai_client.chat(
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        tier="fast",
        response_format="json"
    )

    print("Success:", res.get("success"))
    print("Model:", res.get("model"))
    if not res.get("success"):
        print("Error details:", res.get("error"))
    content = res.get("content", "").strip()
    print("Content preview:", content[:200])

    # Strip fences
    if content.startswith("```"):
        lines = content.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        content = "\n".join(lines).strip()

    try:
        parsed = json.loads(content)
        findings = parsed.get("findings", [])
        print(f"Total findings returned: {len(findings)}")
        valid_findings = []
        for f_item in findings:
            line_no = f_item.get("line")
            evidence = f_item.get("evidence", "")
            if not isinstance(line_no, int) or line_no < 1 or line_no > len(source_lines):
                print(f"  [INVALID LINE] Dropping finding: line {line_no} out of range 1..{len(source_lines)}")
                continue
            actual_line = source_lines[line_no - 1]
            if evidence not in actual_line:
                print(f"  [INVALID EVIDENCE] Dropping finding: '{evidence}' not in line {line_no}: '{actual_line}'")
                continue
            print(f"  [VALID] {f_item.get('id')} ({f_item.get('severity')}) at line {line_no}: '{evidence}'")
            valid_findings.append(f_item)
        print(f"Final valid findings count: {len(valid_findings)}")
    except Exception as e:
        print(f"JSON parse error: {e}")

test_stage12_prompt("examples/telugu/task_scheduler_engine.vital", "Telugu")
test_stage12_prompt("examples/security_lab/hindi/sec_auth_account_hi.vital", "Hindi")
