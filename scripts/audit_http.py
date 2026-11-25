"""Audit the explorer using Flask HTTP requests in an isolated copy of the project."""
import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
import uuid
import unicodedata
from collections import Counter
from contextlib import chdir, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(source):
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def envelope(source, path, language, revision):
    normalized = unicodedata.normalize("NFC", source.removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n"))
    return dict(source=source, file_id=path, language=language, revision_id=digest(normalized)[:12], source_revision=revision)


def observe(client, stages, code, language, revision, path):
    payload = dict(code=code, language=language, source_revision=revision,
                   run_id=str(uuid.uuid4()), use_ai_security=False, pause_on_error=True)
    payload.update(envelope(code, path, language, revision))
    statuses = dict.fromkeys(stages, "pending")
    groups = {}
    if client.application.config.get("AUDIT_SYNC"):
        response = client.post("/api/pipeline/run", json=payload)
        events = [dict(stage_id=s["id"], stage_status=s["status"], details=s["details"])
                  for s in response.json["stages"]]
    else:
        response = client.post("/api/pipeline/stream", json=payload)
        events = [json.loads(line[5:]) for line in response.get_data(as_text=True).splitlines()
                  if line.startswith("data:")]
        if not events or events[-1]["event"] not in ("pipeline_finish", "pipeline_paused"):
            raise RuntimeError("Incomplete event stream")
    for event in events:
        stage = event.get("stage_id")
        if stage in statuses:
            statuses[stage] = event["stage_status"]
            for finding in event.get("details", {}).get("findings", []):
                groups.setdefault(stage, {})[finding["id"]] = finding
    scan = client.post("/api/security/scan", json=dict(code=code, use_ai=False, **envelope(code, path, language, revision)))
    for finding in scan.json["findings"]:
        stage = {"lexical": "lexical_analysis", "semantic": "semantic_analysis",
                 "parser": "syntax_analysis"}.get(finding.get("stage_id"), "security_analysis")
        groups.setdefault(stage, {})[finding["id"]] = finding
    return statuses, groups


def labels(groups):
    return ", ".join(dict.fromkeys(f.get("rule_id", fid) + "@" + str(f.get("line"))
                    for findings in groups.values() for fid, f in findings.items()))


def implementation_notes():
    lines = [
        "## Cascade investigation", "",
        "- Apply in ide.js restarts runCompiler(null, true). The tracker starts with Source Input on the submitted text. A partial restart does not explain the observed behavior.",
        "- handlePipelineEvent adopts a mismatched run ID before the first event and does not compare source hashes. A late stream can update a newly edited buffer.",
        "- openFixAllModal declares applied inside the results-panel block and reads it outside. A browser ReferenceError can prevent opening the preview after HTTP succeeds.",
        "- The three hashes per successful Apply compare the simulated editor, working copy read as text, and subsequent demo-content response. The existing Apply route looks up and saves without a language; demo-content reads with a language hint.",
        "- FastStageValidator and the security suggestion cache include a source digest and analyzer version, but omit file identity. The model response cache in ai_remediation_engine also omits the analyzer version. Each HTTP pipeline run constructs its own tracker.",
        "- apply_span_patch falls through to replacement after an expected-content mismatch. _apply_snippet_to_source first replaces the first matching text regardless of the requested line. Neither guarantees preview identity.",
        "- validate_ai_patch uses script and keyword heuristics. A successful compiler run cannot establish that newly inserted keywords belong to the active language.",
        "- validate_all_prerequisites checks its stages 1–10 validator, then rejects any parser/lexer error before comparing baseline signatures. An existing error can therefore cause rejection.",
        "- verify_repair falls back to a question mark if no remaining ID matches and no line suffix can be parsed. Its delimiter fallback counts raw braces. These messages are possible even when absent from a particular Fix All run.",
        "- src/main.py Compiler.run_parser, DiagnosticNormalizer.analyze_delimiters, ReadOnlyAnalysisTools.check_bracket_balance and the security analyzer all implement delimiter logic. src/semantic.py supplies the pipeline semantic analyzer; check_undefined_variables and the security scanner check names independently. BASE_BUILTIN_NAMES and VITAL_BUILTINS are distinct lists.",
        "- The editor undo ID already has a fallback for both spellings. src/parser.py and web/unified_diagnostics.py do not exist in this checkout.",
        "", "## Rule ID source locations", "",
        "Literal references include emissions, mappings, registry expectations and repair consumers. Runtime IDs may add line or sequence suffixes.", "",
    ]
    locations = {}
    for folder in ("src", "web"):
        paths = []
        for directory, children, filenames in os.walk(ROOT / folder):
            children[:] = [child for child in children if child not in {"venv", "__pycache__"}]
            paths.extend(Path(directory) / name for name in filenames)
        for path in sorted(paths):
            if path.suffix not in {".py", ".js", ".json"}:
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
                for rule in sorted(set(re.findall(r"\b(?:SEC-[A-Z]+|SEM|SYN|OPT|IR|LEX|SRC)-[A-Z0-9]+\b", line))):
                    locations.setdefault(rule, []).append(f"{path.relative_to(ROOT).as_posix()}:{number}")
    return lines + [f"- {rule} — {', '.join(refs)}" for rule, refs in sorted(locations.items())]


def audit(client, stages, file, store):
    start = time.monotonic()
    path, lang = file["path"], file["language"]
    loaded = client.get("/api/demo-content", query_string={"path": path}).json
    code, revision = loaded["code"], loaded["source_revision"]
    statuses, groups = observe(client, stages, code, lang, revision, path)
    before = list(statuses.values())
    initial = labels(groups)
    rejects, manual, hashes = [], [], []
    fix_seconds = 0.0
    seen = {digest(code)}
    for iteration in range(13):
        for stage in stages:
            diagnostics = list(groups.get(stage, {}).values())
            if not diagnostics:
                continue
            if iteration == 12:
                rejects.append("Audit iteration limit reached")
                break
            for finding in diagnostics:
                finding.update(revision_id=revision, validation_status="still_detected")
                finding.setdefault("identifier", "")
            fix_start = time.monotonic()
            result = client.post("/api/ai/fix-all", json=dict(stage_id=stage, source_code=code,
                file_path=path, diagnostics=diagnostics, **envelope(code, path, lang, revision))).json
            fix_seconds += time.monotonic() - fix_start
            for field, target in (("rejected_fixes", rejects), ("manual_fixes", manual)):
                for item in result.get(field, []):
                    target.append(f"{item.get('rule_id', item.get('id'))}: {item.get('reason') or item.get('title')}")
            proposed = result.get("proposed_source")
            if not proposed or proposed == code or not result.get("applied_fixes", result.get("fixes")):
                if result.get("error"):
                    rejects.append(result["error"])
                continue
            apply_start = time.monotonic()
            applied = client.post("/api/ai/apply-fix", json=dict(file_path=path, code=proposed,
                stage_id=stage, finding_id="", preview_revision=result["revision_id"],
                proposed_hash=result["proposed_hash"], **envelope(code, path, lang, revision))).json
            fix_seconds += time.monotonic() - apply_start
            if not applied.get("success"):
                rejects.append(applied["error"])
                continue
            code, revision = proposed, applied["source_revision"]
            disk = list(store.rglob(Path(path).name))
            disks = [digest(p.read_text(encoding="utf-8")) for p in disk
                     if p.as_posix().endswith("/" + path)]
            reload = client.get("/api/demo-content", query_string={"path": path}).json
            hashes.append(dict(editor=digest(code), disk=disks, server=reload["content_hash"]))
            statuses, groups = observe(client, stages, code, lang, revision, path)
            break
        else:
            break
        if digest(code) in seen:
            break
        seen.add(digest(code))
    repeated, again = observe(client, stages, code, lang, revision, path)
    return dict(file=path, language=lang, fix_seconds=round(fix_seconds, 4), repeat_stable=(repeated == statuses and labels(again) == labels(groups)), **dict(zip(stages, before)), findings_before=initial,
                findings_after=labels(groups), rejected=rejects, manual=manual, apply_hashes=hashes,
                seconds=round(time.monotonic()-start, 2), final_before=before[-1],
                final_after=statuses[stages[-1]], mandatory_after=list(statuses.values())[:10],
                reached_14="Y" if statuses[stages[-1]] in ("completed", "passed", "warning") else "N")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "docs/AUDIT_BEFORE.md")
    parser.add_argument("--security-lab", action="store_true")
    parser.add_argument("--sync", action="store_true", help="Use the browser's synchronous HTTP fallback")
    args = parser.parse_args()
    if os.environ.get("VITAL_AI_DISABLED") != "1":
        parser.error("Set VITAL_AI_DISABLED=1 first")
    out = args.output.resolve()
    rows = []
    with tempfile.TemporaryDirectory() as temp:
        copy = Path(temp)
        for name in ("examples", "web", "src"):
            shutil.copytree(ROOT / name, copy / name,
                            ignore=shutil.ignore_patterns("__pycache__", "working_copies", "venv"))
        (copy / "tests").mkdir()
        sys.path.insert(0, temp)
        with chdir(temp), open(os.devnull, "w", encoding="utf-8") as quiet, redirect_stdout(quiet):
            from web.server import app
            app.config["AUDIT_SYNC"] = args.sync
            client = app.test_client()
            demos = client.get("/api/demos").json["data"]["demos"]
            stages = [s["id"] for s in client.get("/api/pipeline/stages").json["stages"]]
            for file in demos:
                if args.security_lab and not file["is_security_lab"]:
                    continue
                rows.append(audit(client, stages, file, copy / "examples/saved/working_copies"))
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.with_suffix(".csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=rows[0])
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, ensure_ascii=False) if isinstance(v, list) else v for k,v in row.items()})
    columns = list(rows[0])
    lines = ["# HTTP catalog audit", "", "Stage columns record the first stream. A ready report awaits generation.", "",
             "| " + " | ".join(columns) + " |", "|" + "---|" * len(columns)]
    for row in rows:
        lines.append("| " + " | ".join(str(row[k]).replace("|", r"\|").replace("\n", " ") for k in columns) + " |")
    counts = Counter(reason for row in rows for reason in row["rejected"])
    lines.extend(["", "## Ranked patch rejections", ""] + [f"- {n} × {r}" for r,n in counts.most_common()])
    lines.append(f"\nStage 14 reached after Fix All: {sum(r['reached_14']=='Y' for r in rows)}/{len(rows)}")
    if out.stem == "AUDIT_BEFORE":
        lines.extend(["", *implementation_notes()])
    else:
        lines.extend([f"Mandatory stages green: {sum(all(s == 'completed' for s in r['mandatory_after']) for r in rows)}/{len(rows)}",
                      f"Stable repeats: {sum(r['repeat_stable'] for r in rows)}/{len(rows)}",
                      f"Slowest Fix All plus Apply: {max(r['fix_seconds'] for r in rows):.3f} seconds"])
    report = "\n".join(lines) + "\n"
    out.write_text(report, encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()
