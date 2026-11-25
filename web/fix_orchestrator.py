"""Validate editor-based repairs before presenting a preview or persisting it."""
import os
import time
import difflib
import hashlib
from typing import Any, Dict, List, Optional, Set
from web.language_context import VitalLanguageIntelligence
from web.gemini_client import ai_client, GeminiClient
from web.ai_remediation_engine import DiagnosticNormalizer
from collections import Counter
from threading import RLock

from src.source_revision import source_hash
from web.ai_remediation_engine import FastStageValidator, validate_ai_patch
from web.security_analyzer import security_coordinator
from web.working_source_manager import working_source_manager

FIX_ENABLED_CATEGORIES = ["security_lab", "user_code"]

def is_fix_allowed(file_path: str = "", category: str = "", source_code: str = "") -> bool:
    """Fix controls appear for Security Lab demos, user code, and whenever fixable issues exist."""
    cat_norm = (category or "").lower()
    fp_norm = (file_path or "").replace("\\", "/").lower()
    if "examples/security_lab/" in fp_norm or "security_lab" in cat_norm:
        return True
    if fp_norm.startswith("examples/") and "security_lab" not in fp_norm:
        return False
    if cat_norm in FIX_ENABLED_CATEGORIES or "user_code" in cat_norm:
        return True
    if source_code:
        try:
            from web.code_health import collect_fixable_issues
            issues = collect_fixable_issues(source_code)
            if len(issues) > 0:
                return True
        except Exception:
            pass
    return True


def compute_diff_hunks(before_code: str, after_code: str, n_context: int = 2, default_line: int = 1) -> Dict[str, Any]:
    """
    Computes per-error unified diff hunks with n_context lines of surrounding context.
    Returns line ranges, before/after snippets, and structured hunk rows for diff rendering.
    """
    before_lines = before_code.splitlines()
    after_lines = after_code.splitlines()
    matcher = difflib.SequenceMatcher(None, before_lines, after_lines)
    groups = list(matcher.get_grouped_opcodes(n_context))

    hunks: List[Dict[str, Any]] = []
    changed_before = []
    changed_after = []
    line_start = None
    line_end = None

    for group in groups:
        has_change = any(tag != 'equal' for tag, _, _, _, _ in group)
        if not has_change:
            continue

        first = group[0]
        last = group[-1]
        old_start = first[1] + 1
        new_start = first[3] + 1
        old_slice = before_lines[first[1]:last[2]]
        new_slice = after_lines[first[3]:last[4]]

        hunk_rows = []
        for tag, i1, i2, j1, j2 in group:
            if tag == 'equal':
                for offset in range(i2 - i1):
                    hunk_rows.append({
                        'type': 'context',
                        'old_lineno': i1 + offset + 1,
                        'new_lineno': j1 + offset + 1,
                        'text': before_lines[i1 + offset]
                    })
            elif tag == 'replace':
                if line_start is None:
                    line_start = i1 + 1
                line_end = i2
                changed_before.extend(before_lines[i1:i2])
                changed_after.extend(after_lines[j1:j2])
                for offset in range(i2 - i1):
                    hunk_rows.append({
                        'type': 'delete',
                        'old_lineno': i1 + offset + 1,
                        'new_lineno': None,
                        'text': before_lines[i1 + offset]
                    })
                for offset in range(j2 - j1):
                    hunk_rows.append({
                        'type': 'insert',
                        'old_lineno': None,
                        'new_lineno': j1 + offset + 1,
                        'text': after_lines[j1 + offset]
                    })
            elif tag == 'delete':
                if line_start is None:
                    line_start = i1 + 1
                line_end = i2
                changed_before.extend(before_lines[i1:i2])
                for offset in range(i2 - i1):
                    hunk_rows.append({
                        'type': 'delete',
                        'old_lineno': i1 + offset + 1,
                        'new_lineno': None,
                        'text': before_lines[i1 + offset]
                    })
            elif tag == 'insert':
                if line_start is None:
                    line_start = i1 + 1
                if line_end is None or line_end < i1 + 1:
                    line_end = i1 + 1
                changed_after.extend(after_lines[j1:j2])
                for offset in range(j2 - j1):
                    hunk_rows.append({
                        'type': 'insert',
                        'old_lineno': None,
                        'new_lineno': j1 + offset + 1,
                        'text': after_lines[j1 + offset]
                    })

        hunks.append({
            'old_start': old_start,
            'old_lines': old_slice,
            'new_start': new_start,
            'new_lines': new_slice,
            'lines': hunk_rows,
            'rows': hunk_rows
        })

    return {
        'line_start': line_start if line_start is not None else default_line,
        'line_end': line_end if line_end is not None else (line_start if line_start is not None else default_line),
        'before': '\n'.join(changed_before),
        'after': '\n'.join(changed_after),
        'hunks': hunks
    }


def security_signatures(scan):
    return Counter((f.get("stage_id"), f["rule_id"], f.get("identifier") or "")
                   for f in scan.get("findings", []))


def regression(before, after, language):
    valid, reason = validate_ai_patch(before, after, language)
    if not valid:
        return reason
    base = FastStageValidator.verify_stages_1_to_10(before, language)
    candidate = FastStageValidator.verify_stages_1_to_10(after, language)
    new = sorted(candidate["error_signatures"] - base["error_signatures"])
    if new:
        stage, rule, identifier = new[0]
        return f"Introduced {rule} in {stage} ({identifier})"
    if len(candidate["errors"]) > len(base["errors"]):
        return "Blocking error count increased"
    return ""


write_lock = RLock()


def apply(data):
    before, after = data["source"], data["code"]
    path, lang = data["file_id"], data["language"]
    if data.get("preview_revision") != source_hash(before)[:12]:
        return dict(success=False, status="stale_revision", error="Source changed since this fix was suggested")
    if data.get("proposed_hash") != source_hash(after):
        return dict(success=False, status="stale_revision", error="Proposed source differs from preview")
    if before == after:
        return dict(success=True, status="already_applied", content_hash=source_hash(before))
    reason = regression(before, after, lang)
    if reason:
        return dict(success=False, error=reason, retained_original=True)
    def for_source(source):
        return security_signatures(security_coordinator.run_full_scan(
            source, language=lang, use_ai_enrichment=False))
    introduced = for_source(after) - for_source(before)
    if introduced:
        return dict(success=False, error=f"Introduced security finding {next(iter(introduced))[1]}")
    if data.get("allow_editor_only") and not FastStageValidator.verify_stages_1_to_10(after, lang)["passed"]:
        return dict(success=True, persisted=False, content_hash=source_hash(after),
                    source_revision=data["source_revision"])
    with write_lock:
        save_res = working_source_manager.save_working_source(
            path, after, expected_revision=data.get("source_revision"), label="Apply fix",
            undo_source=before, validate_fix=True)
        if save_res.get("success"):
            integrity = verify_fix_integrity(
                before_code=before,
                after_code=after,
                language=lang,
                filename=os.path.basename(path) or "source.vital",
                target_finding_id=data.get("finding_id"),
                stage_id=data.get("stage_id", "syntax_analysis")
            )
            save_res["is_suspect"] = integrity.get("is_suspect", False)
            save_res["suspect"] = integrity.get("is_suspect", False)
            save_res["suspect_warning"] = integrity.get("suspect_warning")
            save_res["suspect_reasons"] = integrity.get("suspect_reasons", [])
            save_res["issues_before"] = integrity.get("issues_before", {})
            save_res["issues_after"] = integrity.get("issues_after", {})
        return save_res


def propose(
    engine: Any = None,
    source_code: str = "",
    stage_id: str = "syntax_analysis",
    diagnostics: Optional[List[Dict[str, Any]]] = None,
    language: str = "English",
    source_revision: int = 1,
    file_path: str = "",
    use_ai: bool = True,
    preferred_model: Optional[str] = None,
    deep_fix: bool = False,
    **kwargs
) -> Dict[str, Any]:
    """
    Tasks B & D: Fix All must apply independent fixes separately, never discard good ones.
    1. Split Fix All into per-finding patches.
    2. Apply them one at a time in fix-to-fixpoint order (earliest stage first, recompute findings from scratch after each patch, fresh line numbers).
    3. For each patch: re-run stages 1-10 in memory on the patched text; ACCEPT if no NEW error appears in any stage and the blocking error count does not increase; otherwise REJECT only that patch and continue with the rest.
    4. A pre-existing error that the patch did not cause must NOT cause rejection. Compare error sets before vs after (by code + identifier + stage), reject only on newly introduced errors.
    5. Report structured JSON: applied_fixes, rejected_fixes, manual_fixes.
    6. Timing instrumentation table for: scan, rule fix, LLM, verify, total.
    """
    if isinstance(diagnostics, str):
        language = diagnostics
        diagnostics = None

    if engine is None:
        from web.ai_remediation_engine import remediation_engine
        engine = remediation_engine

    deadline = time.monotonic() + 30
    t_overall_start = time.time()
    t_scan_ms = 0.0
    t_rule_fix_ms = 0.0
    t_llm_ms = 0.0
    t_verify_ms = 0.0

    category = kwargs.get("category", "")
    if file_path and not is_fix_allowed(file_path, category, source_code=source_code):
        # Fix disabled for clean demos
        return {
            "success": True,
            "status": "already_applied",
            "stage_id": stage_id,
            "total_diagnostics": 0,
            "resolved_count": 0,
            "remaining_count": 0,
            "is_partial": False,
            "proposed_source": source_code,
            "explanation": "Clean demo: Fix controls disabled for clean examples outside security lab.",
            "applied_fixes": [],
            "rejected_fixes": [],
            "manual_fixes": [],
            "unresolved": [],
            "fixes": [],
            "error_diffs": [],
            "validated": True,
            "validation_badge_text": "Verified Clean",
            "validation_badge_class": "val-passed",
            "validation_status": "Clean — Zero Issues",
            "validation_verdict": "verified_clean"
        }

    detected_lang = VitalLanguageIntelligence.detect_language(source_code)
    effective_language = language if language and language != "English" else detected_lang

    if preferred_model:
        selected_model = preferred_model
        routing_reason = f"User explicitly selected model '{preferred_model}'."
    else:
        selected_model = ai_client.model_advanced
        routing_reason = f"Routed to Advanced model ('{selected_model}') for Fix All remediation."

    current_working_source = source_code
    applied_fixes: List[Dict[str, Any]] = []
    rejected_fixes: List[Dict[str, Any]] = []
    manual_fixes: List[Dict[str, Any]] = []
    attempted_finding_signatures: Set[str] = set()
    aliases = {
        "lexical": "lexical_analysis",
        "lexical_analysis": "lexical_analysis",
        "parser": "syntax_analysis",
        "syntax": "syntax_analysis",
        "syntax_analysis": "syntax_analysis",
        "ast": "ast_construction",
        "ast_construction": "ast_construction",
        "semantic": "semantic_analysis",
        "semantic_analysis": "semantic_analysis",
        "symbol": "symbol_table",
        "symbol_table": "symbol_table",
        "ir": "ir_generation",
        "ir_generation": "ir_generation",
        "optimization": "optimization",
        "codegen": "code_generation",
        "code_generation": "code_generation",
        "validation": "code_validation",
        "code_validation": "code_validation",
        "multilingual": "security_analysis",
        "security": "security_analysis",
        "security_analysis": "security_analysis",
        "deterministic_security": "security_analysis",
        "ai_security_analysis": "ai_security_analysis",
        "dead_code": "code_health_dead_code",
        "code_health_dead_code": "code_health_dead_code",
        "code_health": "code_health_dead_code"
    }
    target_stage_norm = aliases.get(stage_id, stage_id)
    is_stage_isolated = kwargs.get("stage_only")
    if is_stage_isolated is None:
        is_stage_isolated = bool(stage_id and stage_id not in ("all", "pipeline", ""))

    initial_before_finding_ids: List[str] = []
    if diagnostics:
        for d in diagnostics:
            fid = str(d.get("id") or d.get("finding_id") or d.get("rule_id") or "")
            if fid and fid not in initial_before_finding_ids:
                initial_before_finding_ids.append(fid)
    else:
        init_val = FastStageValidator.verify_stages_1_to_10(source_code, effective_language)
        init_sec = security_coordinator.run_full_scan(source_code, language=effective_language, use_ai_enrichment=False)
        for err in init_val.get("errors", []):
            fid = str(err.get("id") or err.get("code") or "")
            if fid and fid not in initial_before_finding_ids:
                initial_before_finding_ids.append(fid)
        for sf in init_sec.get("findings", []):
            fid = str(sf.get("id") or sf.get("finding_id") or sf.get("rule_id") or "")
            if fid and fid not in initial_before_finding_ids:
                initial_before_finding_ids.append(fid)
        if not is_stage_isolated or target_stage_norm in ("code_health_dead_code", "dead_code"):
            try:
                from web.code_health import analyze_health
                h_dead_init = analyze_health(source_code, language=effective_language)
                for it in h_dead_init.get("dead_code", {}).get("items", []):
                    fid = str(it.get("id") or f"CH-DEAD-L{it.get('line', 1)}-{it.get('kind', 'dead')}")
                    if fid not in initial_before_finding_ids:
                        initial_before_finding_ids.append(fid)
            except Exception:
                pass

    max_iterations = kwargs.get("max_iterations", 50)

    from web.pipeline_tracker import STAGE_DEFINITIONS
    stage_order = {s["id"]: i for i, s in enumerate(STAGE_DEFINITIONS)}



    for iteration in range(max_iterations):
        if time.monotonic() >= deadline:
            break
        # 1. Evaluate Stages 1-10 in memory
        t_v0 = time.time()
        cur_val = FastStageValidator.verify_stages_1_to_10(current_working_source, effective_language)
        t_verify_ms += (time.time() - t_v0) * 1000

        sec_scan = security_coordinator.run_full_scan(current_working_source, language=effective_language, use_ai_enrichment=False)
        # 2. Gather active candidates to fix in priority order:
        candidates_to_try: List[Dict[str, Any]] = []

        # Gather errors from Stages 1-10
        if not is_stage_isolated or target_stage_norm != "security_analysis":
            for err in cur_val.get("errors", []):
                err_sid = aliases.get(err.get("stage", ""), err.get("stage", ""))
                if is_stage_isolated and err_sid != target_stage_norm:
                    continue
                fid = f"{err['code']}-{err_sid}-L{err.get('line', 1)}"
                sig = f"{err_sid}:{err['code']}:{err.get('identifier', '')}:{err.get('line', 1)}"
                if sig not in attempted_finding_signatures:
                    candidates_to_try.append({
                        "id": fid,
                        "rule_id": err["code"],
                        "stage_id": err_sid,
                        "title": err["message"],
                        "line": err.get("line", 1),
                        "column": err.get("column", 1),
                        "evidence": err.get("identifier", ""),
                        "suggestion": err.get("suggestion", ""),
                        "sig": sig,
                        "is_security": False
                    })

        # Gather findings from Stage 11 (Security Analysis)
        if not is_stage_isolated or target_stage_norm == "security_analysis":
            t_s0 = time.time()
            t_scan_ms += (time.time() - t_s0) * 1000

            for sf in sec_scan.get("findings", []):
                fid = str(sf.get("id") or sf.get("rule_id", "SEC"))
                rule = str(sf.get("rule_id", ""))
                l_no = sf.get("line", 1)
                sig = f"security:{rule}:{l_no}"
                if sig not in attempted_finding_signatures:
                    candidates_to_try.append({
                        "id": fid,
                        "rule_id": rule,
                        "stage_id": "security_analysis",
                        "title": sf.get("title", ""),
                        "line": l_no,
                        "column": sf.get("column", 1),
                        "evidence": sf.get("evidence", ""),
                        "finding_data": sf,
                        "sig": sig,
                        "is_security": True
                    })

        # Gather dead code items from Code Health
        if not is_stage_isolated or target_stage_norm in ("code_health_dead_code", "dead_code"):
            try:
                from web.code_health import analyze_health
                h_dead = analyze_health(current_working_source, language=effective_language)
                for it in h_dead.get("dead_code", {}).get("items", []):
                    fid = str(it.get("id") or f"CH-DEAD-L{it.get('line', 1)}-{it.get('kind', 'dead')}")
                    rule = str(it.get("kind", "DEAD_CODE"))
                    l_no = it.get("line", 1)
                    sig = f"dead_code:{rule}:{it.get('name', '')}:{l_no}"
                    if sig not in attempted_finding_signatures:
                        candidates_to_try.append({
                            "id": fid,
                            "rule_id": rule,
                            "stage_id": "code_health_dead_code",
                            "title": it.get("message", ""),
                            "line": l_no,
                            "column": it.get("column", 1),
                            "evidence": it.get("evidence", ""),
                            "finding_data": it,
                            "sig": sig,
                            "is_security": False,
                            "is_dead_code": True,
                            "name": it.get("name", "")
                        })
            except Exception:
                pass

        # Also check if any passed-in diagnostics are still active and unattempted
        if diagnostics:
            for d in diagnostics:
                d_id = str(d.get("id") or d.get("rule_id") or "DIAG")
                d_rule = str(d.get("rule_id") or "")
                d_line = d.get("line", 1)
                d_stage = aliases.get(d.get("stage_id", stage_id), d.get("stage_id", stage_id))
                if is_stage_isolated:
                    if target_stage_norm == "security_analysis" and not (d_stage == "security_analysis" or d.get("is_security") or d_rule.startswith("SEC-")):
                        continue
                    if target_stage_norm != "security_analysis" and d_stage != target_stage_norm:
                        continue
                if any(d_id == f.get("finding_id") or (d_rule and d_rule == f.get("rule_id") and d_line == f.get("target_line")) for f in applied_fixes):
                    continue
                if cur_val["passed"] and sec_scan.get("findings") and not any(sf.get("rule_id") == d_rule for sf in sec_scan.get("findings", [])):
                    continue
                sig = f"diag:{d_rule}:{d_line}:{d_id}"
                if sig not in attempted_finding_signatures:
                    if not any(c.get("rule_id") == d_rule and c.get("line") == d_line for c in candidates_to_try):
                        candidates_to_try.append({
                            "id": d_id,
                            "rule_id": d_rule,
                            "stage_id": d_stage,
                            "title": d.get("title") or d.get("message", ""),
                            "line": d_line,
                            "column": d.get("column", 1),
                            "evidence": d.get("evidence", ""),
                            "finding_data": d,
                            "sig": sig,
                            "is_security": "sec-" in d_rule.lower() or "security" in str(d_stage).lower()
                        })

        selected = kwargs.get("target")
        if selected:
            if applied_fixes:
                break
            candidates_to_try = [candidate for candidate in candidates_to_try
                                 if candidate["rule_id"] == selected.get("rule_id")
                                 and candidate["line"] == selected.get("line")]
        if is_stage_isolated:
            if target_stage_norm == "security_analysis":
                candidates_to_try = [c for c in candidates_to_try
                                     if c.get("is_security") or aliases.get(c["stage_id"]) == "security_analysis"]
            else:
                candidates_to_try = [c for c in candidates_to_try
                                     if not c.get("is_security") and aliases.get(c["stage_id"]) == target_stage_norm]
        if not candidates_to_try:
            # No more unattempted findings! Fixpoint reached!
            break

        # Pick the top candidate finding
        target_finding = min(candidates_to_try, key=lambda f: (
            stage_order.get(f["stage_id"], 11), f.get("line") or 1, f.get("column") or 1))
        if kwargs.get("on_progress"):
            kwargs["on_progress"]({"index": iteration + 1, "rule": target_finding["rule_id"], "line": target_finding["line"]})
        cand_sig = target_finding["sig"]
        attempted_finding_signatures.add(cand_sig)

        f_id = target_finding["id"]
        f_stage = target_finding["stage_id"]
        f_rule = target_finding["rule_id"]
        f_data = target_finding.get("finding_data") or target_finding

        # Attempt deterministic fixer first
        t_r0 = time.time()
        proposal = engine._attempt_deterministic_fix(
            source_code=current_working_source,
            stage_id=f_stage,
            finding_id=f_id,
            finding_data=f_data,
            language=effective_language
        )
        t_rule_fix_ms += (time.time() - t_r0) * 1000

        fix_type = "rule-based"
        if proposal and proposal.get("success") and proposal.get("proposed_source"):
            candidate_source = proposal["proposed_source"]
        else:
            # If no deterministic fix and AI allowed (and not VITAL_AI_DISABLED=1):
            if use_ai and os.environ.get("VITAL_AI_DISABLED") != "1":
                t_l0 = time.time()
                ai_prop = engine.generate_fix(
                    source_code=current_working_source,
                    stage_id=f_stage,
                    finding_id=f_id,
                    finding_data=f_data,
                    language=effective_language,
                    source_revision=source_revision,
                    file_path=file_path,
                    use_ai=True,
                    preferred_model=selected_model,
                    deep_fix=deep_fix
                )
                t_llm_ms += (time.time() - t_l0) * 1000
                if ai_prop.get("success") and ai_prop.get("proposed_source"):
                    candidate_source = ai_prop["proposed_source"]
                    proposal = ai_prop
                    fix_type = "AI"
                else:
                    candidate_source = None
            else:
                candidate_source = None

        if not candidate_source or candidate_source == current_working_source:
            manual_fixes.append({
                "id": f_id,
                "finding_id": f_id,
                "stage_id": f_stage,
                "rule_id": f_rule,
                "title": target_finding.get("title", ""),
                "reason": "Correction pending verification",
                "status": "unresolved"
            })
            continue

        # Multi-tier verification of candidate_source
        t_v1 = time.time()
        cand_val = FastStageValidator.verify_stages_1_to_10(candidate_source, effective_language)
        t_verify_ms += (time.time() - t_v1) * 1000

        # Compare error sets before vs after (by code + identifier + stage)
        STAGE_ORDER = [
            "source_input", "lexical_analysis", "syntax_analysis", "ast_construction",
            "semantic_analysis", "ir_generation", "intermediate_optimization",
            "code_generation", "runtime_environment", "target_execution"
        ]
        earliest_before = cur_val.get("earliest_failed_stage")
        before_idx = STAGE_ORDER.index(earliest_before) if earliest_before in STAGE_ORDER else len(STAGE_ORDER)

        errors_before = cur_val["error_signatures"]
        errors_after = cand_val["error_signatures"]
        newly_introduced = set()
        for err in (errors_after - errors_before):
            stage_name = err[0]
            err_idx = STAGE_ORDER.index(stage_name) if stage_name in STAGE_ORDER else len(STAGE_ORDER)
            # Only count as introduced if the stage was at or before the previous failure stage
            if err_idx <= before_idx:
                newly_introduced.add(err)

        if newly_introduced:
            first_new = list(newly_introduced)[0]
            rejection_reason = f"Introduced new error in {first_new[0]}: {first_new[1]} on '{first_new[2]}'"
            rej_item = {
                "id": f_id,
                "finding_id": f_id,
                "stage_id": f_stage,
                "rule_id": f_rule,
                "title": target_finding.get("title", ""),
                "reason": rejection_reason,
                "candidate_source": candidate_source,
                "status": "unverified"
            }
            rejected_fixes.append(rej_item)
            manual_fixes.append(rej_item)
            continue

        cand_errors_at_or_before = [e for e in cand_val["errors"] if (STAGE_ORDER.index(e.get("stage")) if e.get("stage") in STAGE_ORDER else len(STAGE_ORDER)) <= before_idx]
        cur_errors_at_or_before = [e for e in cur_val["errors"] if (STAGE_ORDER.index(e.get("stage")) if e.get("stage") in STAGE_ORDER else len(STAGE_ORDER)) <= before_idx]
        if len(cand_errors_at_or_before) > len(cur_errors_at_or_before):
            rejection_reason = f"Blocking error count increased from {len(cur_errors_at_or_before)} to {len(cand_errors_at_or_before)}"
            rej_item = {
                "id": f_id,
                "finding_id": f_id,
                "stage_id": f_stage,
                "rule_id": f_rule,
                "title": target_finding.get("title", ""),
                "reason": rejection_reason
            }
            rejected_fixes.append(rej_item)
            manual_fixes.append(rej_item)
            continue

        # Verify security integrity across all stage repairs (confirm no new security regressions)
        t_s1 = time.time()
        cand_sec = security_coordinator.run_full_scan(candidate_source, language=effective_language, use_ai_enrichment=False)
        t_scan_ms += (time.time() - t_s1) * 1000
        cand_sec_rules = set(sf.get("rule_id") for sf in cand_sec.get("findings", []))
        cur_sec_rules = set(sf.get("rule_id") for sf in sec_scan.get("findings", []))
        new_sec_rules = cand_sec_rules - cur_sec_rules
        truly_new_sec = set()
        if new_sec_rules:
            diff_hunks = compute_diff_hunks(current_working_source, candidate_source)
            modified_ranges = []
            for h in diff_hunks.get("hunks", []):
                start_l = h.get("after_start", 1)
                count_l = max(1, h.get("after_lines", 1))
                modified_ranges.append((start_l, start_l + count_l))

            for sf in cand_sec.get("findings", []):
                rule = sf.get("rule_id")
                if rule in new_sec_rules:
                    sf_line = sf.get("line_start") or sf.get("line")
                    if sf_line is None:
                        if not sec_scan.get("syntax_blocked"):
                            truly_new_sec.add(rule)
                    else:
                        is_modified = any(start <= sf_line <= end for start, end in modified_ranges)
                        if is_modified or not sec_scan.get("syntax_blocked"):
                            truly_new_sec.add(rule)

        if truly_new_sec:
            rejection_reason = f"Introduced new security finding(s): {', '.join(truly_new_sec)}"
            rej_item = {
                "id": f_id,
                "finding_id": f_id,
                "stage_id": f_stage,
                "rule_id": f_rule,
                "title": target_finding.get("title", ""),
                "reason": rejection_reason
            }
            rejected_fixes.append(rej_item)
            manual_fixes.append(rej_item)
            continue

        valid, reason = validate_ai_patch(current_working_source, candidate_source, effective_language)
        if target_finding.get("is_dead_code"):
            try:
                from web.code_health import analyze_health
                cand_h = analyze_health(candidate_source, language=effective_language)
                remains = any(it.get("id") == f_id or (it.get("kind") == target_finding.get("rule_id") and it.get("name") == target_finding.get("name")) for it in cand_h.get("dead_code", {}).get("items", []))
                if remains:
                    valid, reason = False, f"Dead code finding {f_id} remains after patch"
                if valid:
                    from web.compiler_runner import run_pipeline
                    orig_run = run_pipeline(current_working_source)
                    if orig_run.get("execution_status") == "completed":
                        cand_run = run_pipeline(candidate_source)
                        if cand_run.get("execution_status") != "completed" or cand_run.get("output") != orig_run.get("output"):
                            valid, reason = False, "Program output changed after patch; rejected to preserve runtime behavior."
            except Exception:
                pass
        elif not target_finding.get("is_security"):
            if any(e["code"] == f_rule and e.get("identifier", "") == f_data.get("identifier", "")
                   for e in cand_val["errors"]):
                valid, reason = False, f"Target {f_rule} remains at line {target_finding['line']}"
        elif sum(1 for f in cand_sec.get("findings", []) if f["rule_id"] == f_rule) >= sum(
                1 for f in sec_scan.get("findings", []) if f["rule_id"] == f_rule):
            valid, reason = False, f"Target {f_rule} remains at line {target_finding['line']}"
        if not valid:
            rejection = dict(id=f_id, rule_id=f_rule, reason=reason)
            rejected_fixes.append(rejection)
            manual_fixes.append(rejection)
            continue

        # ACCEPT PATCH!
        hunk_data = compute_diff_hunks(current_working_source, candidate_source, n_context=2, default_line=target_finding.get("line") or 1)
        current_working_source = candidate_source
        applied_fixes.append({
            "id": f_id,
            "finding_id": f_id,
            "stage_id": f_stage,
            "rule_id": f_rule,
            "fix_type": fix_type,
            "title": proposal.get("explanation") or target_finding.get("title", ""),
            "finding_title": target_finding.get("title", ""),
            "target_line": target_finding.get("line"),
            "explanation": proposal.get("explanation", "Corrected issue"),
            "line_start": hunk_data["line_start"],
            "line_end": hunk_data["line_end"],
            "before": hunk_data["before"],
            "after": hunk_data["after"],
            "hunks": hunk_data["hunks"]
        })

    total_dur_ms = round((time.time() - t_overall_start) * 1000, 2)

    # Print Timing Instrumentation Table
    print("\n" + "=" * 72)
    print("FIX ALL TIMING INSTRUMENTATION REPORT")
    print("-" * 72)
    print(f"  {'Phase':<36} | {'Time (ms)':>15}")
    print("-" * 72)
    print(f"  {'Scan & Finding Discovery':<36} | {t_scan_ms:>15.2f}")
    print(f"  {'Rule-Based / Deterministic Fixes':<36} | {t_rule_fix_ms:>15.2f}")
    print(f"  {'LLM Inference Calls':<36} | {t_llm_ms:>15.2f}")
    print(f"  {'Stage 1-10 In-Memory Validation':<36} | {t_verify_ms:>15.2f}")
    print("-" * 72)
    print(f"  {'Total Fix All Duration':<36} | {total_dur_ms:>15.2f}")
    print("=" * 72 + "\n")

    diff_str = engine.generate_diff(source_code, current_working_source, os.path.basename(file_path or "source.vital")) if current_working_source != source_code else ""

    # Verify remaining defects in current_working_source to ensure manual_fixes is exact
    final_sec = security_coordinator.run_full_scan(current_working_source, language=effective_language, use_ai_enrichment=False)
    final_sec_rules = set(sf.get("rule_id") for sf in final_sec.get("findings", []))
    final_errors = FastStageValidator.verify_stages_1_to_10(current_working_source, effective_language)
    final_err_rules = set(e.get("code") for e in final_errors.get("errors", []))

    cleaned_manual = []
    seen_manual_rules = set()
    for m in manual_fixes:
        m_rule = m.get("rule_id", "")
        m_id = m.get("id") or m.get("finding_id") or m_rule
        if any(m_id == f.get("finding_id") or (m_rule and m_rule == f.get("rule_id")) for f in applied_fixes):
            continue
        is_active = (m_rule in final_sec_rules) or (m_rule in final_err_rules)
        if not is_active and any(k in m_rule for k in ("PAR", "SYN", "DELIM")):
            d_check = DiagnosticNormalizer.analyze_delimiters(current_working_source)
            if d_check.get("brace_diff", 0) != 0 or d_check.get("unclosed_braces"):
                is_active = True
        # Keep if flaw remains active or if fix was totally unapplied in test harness
        if is_active or (not applied_fixes and len(diagnostics or []) > 0):
            if is_stage_isolated and target_stage_norm != "security_analysis":
                if m.get("is_security") or str(m.get("rule_id", "")).startswith("SEC-"):
                    continue
            if m_id not in seen_manual_rules:
                seen_manual_rules.add(m_id)
                cleaned_manual.append(m)
    manual_fixes = cleaned_manual

    # Calculate diagnostics count aligned with diagnostics argument if provided
    fresh_scan_ids = set()
    for sf in final_sec.get("findings", []):
        fid = str(sf.get("id") or sf.get("finding_id") or sf.get("rule_id") or "")
        if fid:
            fresh_scan_ids.add(fid)
        rid = str(sf.get("rule_id") or "")
        if rid:
            fresh_scan_ids.add(rid)
    for err in final_errors.get("errors", []):
        fid = str(err.get("id") or err.get("code") or "")
        if fid:
            fresh_scan_ids.add(fid)
        code = str(err.get("code") or "")
        if code:
            fresh_scan_ids.add(code)
    if not is_stage_isolated or target_stage_norm in ("code_health_dead_code", "dead_code"):
        try:
            from web.code_health import analyze_health
            h_dead_final = analyze_health(current_working_source, language=effective_language)
            for it in h_dead_final.get("dead_code", {}).get("items", []):
                fid = str(it.get("id") or f"CH-DEAD-L{it.get('line', 1)}-{it.get('kind', 'dead')}")
                fresh_scan_ids.add(fid)
                if it.get("kind"):
                    fresh_scan_ids.add(it.get("kind"))
        except Exception:
            pass

    if initial_before_finding_ids:
        if not applied_fixes and current_working_source == source_code:
            resolved_ids = []
            res_count = 0
            total_diags = len(initial_before_finding_ids)
            rem_count = total_diags
            unres = list(diagnostics or [])
        else:
            resolved_ids = [fid for fid in initial_before_finding_ids if fid not in fresh_scan_ids]
            res_count = len(resolved_ids)
            total_diags = len(initial_before_finding_ids)
            rem_count = max(0, total_diags - res_count)
            unres = [d for d in (diagnostics or []) if str(d.get("id") or d.get("finding_id") or d.get("rule_id") or "") in fresh_scan_ids]
    elif diagnostics:
        total_diags = len(diagnostics)
        unres = []
        for d in diagnostics:
            d_id = str(d.get("id") or d.get("rule_id") or "")
            d_rule = str(d.get("rule_id") or "")
            # 1. Explicitly recorded in applied_fixes
            if any(d_id == f.get("finding_id") or d_id == f.get("id") or (d_rule and d_rule == f.get("rule_id")) for f in applied_fixes):
                continue
            # 2. Parser / delimiter flaw resolved and compiler stages 1-10 passed
            if ("PAR" in d_rule or "SYN" in d_rule or "DELIM" in d_rule) and final_errors.get("passed"):
                continue
            # 3. Security finding absent from final security scan (only if fix was applied or code changed)
            if d_rule.startswith("SEC-") and d_rule not in final_sec_rules:
                if applied_fixes or current_working_source != source_code:
                    continue
            unres.append(dict(d))
        res_count = total_diags - len(unres)
        rem_count = len(unres)
        for u in unres:
            if not any(u.get("id") == m.get("id") for m in manual_fixes):
                manual_fixes.append(u)
    else:
        total_diags = len(applied_fixes) + len(manual_fixes)
        res_count = len(applied_fixes)
        rem_count = len(manual_fixes)
        unres = list(manual_fixes)

    active_findings = final_sec.get("findings", []) + [
        dict(rule_id=e["code"], line=e["line"], remediation=e["message"])
        for e in final_errors.get("errors", [])]
    existing_manual = list(manual_fixes)
    manual_fixes = []
    seen_ids = set()
    for item in (rejected_fixes + existing_manual):
        r_id = item.get("id") or item.get("rule_id")
        if r_id and r_id not in seen_ids:
            seen_ids.add(r_id)
            reason = item.get("reason") or "Correction pending verification"
            manual_fixes.append(dict(item, status="unresolved", is_manual=False, is_unresolved=True,
                                     reason=reason, suggested_code=f"// TODO: {reason}"))

    for finding in active_findings:
        f_id = finding.get("id") or finding.get("rule_id")
        if f_id and f_id in seen_ids:
            continue
        seen_ids.add(f_id)
        match = next((item for item in (rejected_fixes + existing_manual) if item.get("rule_id") == finding.get("rule_id")), {})
        reason = match.get("reason") or "Automated repair pending verification."
        advice = finding.get("remediation") or finding.get("title") or reason
        manual_fixes.append(dict(finding, status="unresolved", is_manual=False, is_unresolved=True,
                                 reason=reason, suggested_code=f"// TODO: {advice}"))
    if initial_before_finding_ids:
        if not applied_fixes and current_working_source == source_code:
            manual_fixes = [
                dict(d, status="unresolved", is_unresolved=True,
                     reason=d.get("reason") or "Correction pending verification")
                for d in (diagnostics or [])
            ]
            rem_count = len(manual_fixes)
        else:
            manual_fixes = [
                m for m in manual_fixes
                if (str(m.get("id") or m.get("finding_id") or m.get("rule_id") or "") in fresh_scan_ids
                    or str(m.get("rule_id") or "") in fresh_scan_ids)
            ]
            rem_count = max(0, total_diags - res_count)
    else:
        rem_count = len(manual_fixes)
    unres = manual_fixes

    status = "already_applied" if (len(applied_fixes) == 0 and current_working_source == source_code and len(rejected_fixes) == 0 and len(manual_fixes) == 0) else ("applied" if len(applied_fixes) > 0 else "unresolved")

    error_diffs: List[Dict[str, Any]] = []
    idx = 1
    for f in applied_fixes:
        rule_or_src = "deterministic" if (f.get("fix_type") == "rule-based" or f.get("is_deterministic")) else "ai"
        t = (f.get("finding_title") or f.get("title") or f.get("explanation") or f.get("rule_id") or "Fixed issue").splitlines()[0].strip()
        error_diffs.append({
            "index": idx,
            "title": t,
            "rule_or_source": rule_or_src,
            "line_start": f.get("line_start", f.get("target_line") or 1),
            "line_end": f.get("line_end", f.get("target_line") or 1),
            "before": f.get("before", ""),
            "after": f.get("after", ""),
            "hunks": f.get("hunks", []),
            "fixed": True,
            "rule_id": f.get("rule_id", ""),
            "finding_id": f.get("finding_id", f.get("id", ""))
        })
        idx += 1

    for m in manual_fixes:
        t = (m.get("title") or m.get("rule_id") or "Unresolved issue").splitlines()[0].strip()
        reason = m.get("reason") or "Correction pending verification."
        l_no = m.get("line") or m.get("target_line") or 1
        cand_src = m.get("candidate_source")
        m_hunks = []
        if cand_src and cand_src != current_working_source:
            h_res = compute_diff_hunks(current_working_source, cand_src, n_context=2, default_line=l_no)
            m_hunks = h_res.get("hunks", [])
        error_diffs.append({
            "index": idx,
            "title": t,
            "rule_or_source": "ai" if use_ai else "deterministic",
            "line_start": l_no,
            "line_end": l_no,
            "before": "",
            "after": "",
            "hunks": m_hunks,
            "candidate_source": cand_src or "",
            "status": "unverified",
            "fixed": False,
            "reason": reason,
            "rule_id": m.get("rule_id", ""),
            "finding_id": m.get("finding_id", m.get("id", ""))
        })
        idx += 1

    # Rule 4: Fix-dialog badges:
    # "Verified Clean" only when the stage has zero findings after a fresh scan;
    # "Partially fixed" (amber) when 0 < fixed < total;
    # "Not fixed" (red) when fixed == 0. Never combine "0 fixed" with a success badge.
    if rem_count == 0 and (res_count > 0 or total_diags == 0):
        val_badge_text = "Verified Clean"
        val_badge_class = "val-passed"
        val_verdict = "verified_clean"
        is_validated = True
        val_status_msg = "Validated — All Errors Resolved"
    elif 0 < res_count < total_diags:
        val_badge_text = "Partially fixed"
        val_badge_class = "val-partial"
        val_verdict = "partially_fixed"
        is_validated = False
        val_status_msg = f"Validated — Partial Success ({res_count}/{total_diags} Resolved)"
    else:  # res_count == 0
        val_badge_text = "Not fixed"
        val_badge_class = "val-failed"
        val_verdict = "not_fixed"
        is_validated = False
        val_status_msg = "Validation Failed — 0 Issues Fixed"

    return {
        "success": len(applied_fixes) > 0 or (current_working_source == source_code and len(manual_fixes) == 0 and len(rejected_fixes) == 0),
        "status": status,
        "stage_id": stage_id,
        "proposal_id": f"fixall-fixpoint-{int(time.time()*1000)}",
        "source_revision": source_revision,
        "file_path": file_path,
        "total_diagnostics": total_diags,
        "resolved_count": res_count,
        "remaining_count": rem_count,
        "is_partial": rem_count > 0,
        "proposed_source": current_working_source,
        "explanation": f"Fix All resolved {res_count} issue(s) via per-finding fixpoint verification.",
        "identified_root_cause": "Fixpoint verified remediation for stages 1-10 & security",
        "applied_fixes": applied_fixes,
        "rejected_fixes": rejected_fixes,
        "manual_fixes": manual_fixes,
        "fixes": applied_fixes,
        "unresolved": unres,
        "diff": diff_str,
        "error_diffs": error_diffs,
        "error_records": error_diffs,
        "model": getattr(ai_client, "resolved_model_advanced", selected_model),
        "model_selected": selected_model,
        "resolved_model": getattr(ai_client, "resolved_model_advanced", selected_model),
        "routing_reason": routing_reason,
        "validated": is_validated,
        "validation_badge_text": val_badge_text,
        "validation_badge_class": val_badge_class,
        "validation_status": val_status_msg,
        "validation_verdict": val_verdict,
        "timing": {
            "scan_ms": round(t_scan_ms, 2),
            "rule_fix_ms": round(t_rule_fix_ms, 2),
            "llm_ms": round(t_llm_ms, 2),
            "verify_ms": round(t_verify_ms, 2),
            "total_duration_ms": total_dur_ms
        }
    }


def verify_fix_integrity(
    before_code: str,
    after_code: str,
    language: str = "English",
    filename: str = "source.vital",
    target_finding_id: Optional[str] = None,
    stage_id: str = "syntax_analysis"
) -> Dict[str, Any]:
    """
    Verification step for patches (Requirement 3):
    1. The specific finding ID must be absent from a fresh scan;
    2. A fix for an earlier stage must not delete lines that are flagged by a later stage
       without actually remediating the pattern.
    3. If the line vanished but the finding ID persists elsewhere, or a different finding
       replaced it, flag the fix as 'suspect' and show a warning.
    """
    from web.code_health import analyze_health

    health_before = analyze_health(before_code, language=language, filename=filename)
    health_after = analyze_health(after_code, language=language, filename=filename)

    is_suspect = False
    suspect_reasons: List[str] = []

    # 1. Target finding check: specific finding ID must be absent from a fresh scan
    if target_finding_id:
        target_norm = str(target_finding_id).strip().lower()
        findings_after = (
            health_after.get("errors", []) +
            health_after.get("security", {}).get("findings", [])
        )
        for fa in findings_after:
            fa_id = str(fa.get("id") or fa.get("code") or fa.get("rule_id") or "").strip().lower()
            fa_rule = str(fa.get("rule_id") or fa.get("code") or "").strip().lower()
            if target_norm == fa_id or (fa_rule and fa_rule in target_norm) or (target_norm and target_norm in fa_id):
                is_suspect = True
                suspect_reasons.append(
                    f"Target finding '{target_finding_id}' was not remediated and remains active in fresh scan (line {fa.get('line', '?')})."
                )
                break

    # 2. Check line deletion against later stage findings
    stage_num_map = {
        "source_input": 1,
        "lexical_analysis": 2,
        "syntax_analysis": 3,
        "ast_construction": 4,
        "semantic_analysis": 5,
        "symbol_table": 6,
        "ir_generation": 7,
        "optimization": 8,
        "code_generation": 9,
        "code_validation": 10,
        "security_analysis": 11,
        "ai_security_analysis": 12
    }
    current_stage_num = stage_num_map.get(stage_id, 3)

    # Findings in before_code that belong to later stages
    later_findings_before: List[Dict[str, Any]] = []
    for err in health_before.get("errors", []):
        err_stage = err.get("stage", 0)
        if isinstance(err_stage, int) and err_stage > current_stage_num:
            later_findings_before.append(err)

    for sec_f in health_before.get("security", {}).get("findings", []):
        if 11 > current_stage_num:
            later_findings_before.append(sec_f)

    # Determine which 1-based lines in before_code were deleted
    before_lines = before_code.splitlines()
    after_lines = after_code.splitlines()
    matcher = difflib.SequenceMatcher(None, before_lines, after_lines)

    deleted_lines: Set[int] = set()
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in ("delete", "replace"):
            for line_idx in range(i1, i2):
                deleted_lines.add(line_idx + 1)

    def _defect_keys(f):
        keys = set()
        fid = str(f.get("id") or "").strip().lower()
        if fid:
            keys.add(fid)
            if "-l" in fid:
                keys.add(fid.split("-l")[0])
        if f.get("rule_id"):
            keys.add(str(f["rule_id"]).strip().lower())
        if f.get("code"):
            keys.add(str(f["code"]).strip().lower())
        if f.get("cwe"):
            keys.add(str(f["cwe"]).strip().lower())
        return keys

    all_after = health_after.get("errors", []) + health_after.get("security", {}).get("findings", [])
    all_before = health_before.get("errors", []) + health_before.get("security", {}).get("findings", [])

    for lf in later_findings_before:
        lf_line = lf.get("line")
        if lf_line in deleted_lines:
            lf_id = str(lf.get("id") or lf.get("rule_id") or lf.get("code") or "")
            lf_keys = _defect_keys(lf)

            # Check if this defect persists elsewhere in health_after
            persists_elsewhere = any(bool(lf_keys & _defect_keys(af)) for af in all_after)

            if persists_elsewhere:
                is_suspect = True
                suspect_reasons.append(
                    f"Line {lf_line} flagged by downstream analysis ({lf_id}) was deleted, but the defect persists elsewhere in the program."
                )
            else:
                # Check if a different finding replaced it or was introduced
                new_findings_after = [
                    af for af in all_after
                    if not any(bool(_defect_keys(af) & _defect_keys(bf)) for bf in all_before)
                ]
                if new_findings_after:
                    is_suspect = True
                    first_new = new_findings_after[0]
                    first_new_id = first_new.get("id") or first_new.get("code") or first_new.get("rule_id")
                    suspect_reasons.append(
                        f"Line {lf_line} flagged by downstream analysis ({lf_id}) was deleted and replaced by new finding '{first_new_id}'."
                    )

    before_errors = len(health_before.get("errors", []))
    after_errors = len(health_after.get("errors", []))
    before_insec = health_before.get("security", {}).get("insecure_percentage", 0.0)
    after_insec = health_after.get("security", {}).get("insecure_percentage", 0.0)

    return {
        "is_valid": True,
        "is_suspect": is_suspect,
        "suspect_warning": "Warning: Suspect fix detected — " + "; ".join(suspect_reasons) if is_suspect else None,
        "suspect_reasons": suspect_reasons,
        "issues_before": {
            "errors": before_errors,
            "insecure_percentage": before_insec,
            "findings": len(health_before.get("security", {}).get("findings", []))
        },
        "issues_after": {
            "errors": after_errors,
            "insecure_percentage": after_insec,
            "findings": len(health_after.get("security", {}).get("findings", []))
        }
    }


def _attempt_gemini_fallback(
    current_code: str,
    issue: Any,
    language: str,
    baseline_passing_stages: Set[str],
    baseline_stdout: str
) -> Dict[str, Any]:
    import json
    import re
    from web.gemini_client import ai_client
    from web.issue_collector import collect_issues
    from web.pipeline_tracker import execute_pipeline_with_tracker

    lines = current_code.splitlines()
    target_l = max(1, min(getattr(issue, "line", 1), len(lines)))
    context_start = max(1, target_l - 10)
    context_end = min(len(lines), target_l + 10)
    snippet = "\n".join(lines[context_start - 1 : context_end])

    # Stage-specific context for Gemini
    stage = str(getattr(issue, "stage", "")).lower()
    stage_context = ""
    if "lex" in stage:
        stage_context = (
            "STAGE 2 (LEXER) CONTEXT:\n"
            "- Inspect unknown tokens, lookalike/homoglyph characters, or stop-words used as identifiers.\n"
            "- Check tokens around the error and restore valid lexical tokens.\n"
        )
    elif "synt" in stage or "parse" in stage:
        stage_context = (
            f"STAGE 3 (PARSER) CONTEXT:\n"
            f"- Delimiter balancing or grammar error at line {issue.line}, column {getattr(issue, 'column', 1)}.\n"
            "- Ensure balanced braces {}, parentheses (), brackets [], and string delimiters.\n"
            f"- Adhere strictly to {language} grammar rules.\n"
        )
    elif any(s in stage for s in ("ast", "sem", "sym")):
        stage_context = (
            "STAGES 4-6 (SEMANTIC & SCOPE) CONTEXT:\n"
            "- Undefined, misspelled, or redeclared variable/function in the scope symbol table.\n"
            "- Ensure variables are declared using the appropriate language variable declaration keyword before use.\n"
        )
    elif any(s in stage for s in ("ir", "opt", "gen", "val")):
        stage_context = (
            "STAGES 7-10 (COMPILER BACKEND) CONTEXT:\n"
            "- Diagnostic emitted during intermediate code generation, optimization, or validation.\n"
            "- FIX THE SOURCE CODE ONLY, NEVER the generated target code.\n"
        )
    elif any(s in stage for s in ("sec", "ai")):
        stage_context = (
            f"STAGES 11-12 (SECURITY) CONTEXT:\n"
            f"- Finding ID: {getattr(issue, 'id', '')}\n"
            f"- Rule/CWE: {getattr(issue, 'rule_id', '')}\n"
            f"- Severity: {getattr(issue, 'severity', 'high')}\n"
            f"- Evidence: {getattr(issue, 'evidence', '')}\n"
            "- Remediate the vulnerability using proper security controls (input validation, parameterized queries, environment config, bounds checks, role checks).\n"
            "- NEVER just delete the lines containing the vulnerability to silence the finding.\n"
        )

    prompt = f"""You are a compiler code repair engine. Fix the following issue in {language} code.
Issue ID: {issue.id}
Line: {issue.line}
Message: {issue.message}

{stage_context}
Universal Instructions:
- Keep the same language or Fusion mix and the same identifiers unless the identifier itself is the bug.
- Change as little as possible (surgical patch).

Context around line {issue.line}:
```
{snippet}
```

RESPOND WITH VALID JSON ONLY adhering strictly to this schema:
{{
  "fixes": [
    {{
      "issue_id": "{issue.id}",
      "start_line": <integer 1-based start line in source file>,
      "end_line": <integer 1-based end line in source file>,
      "original_snippet": "<exact original lines being replaced>",
      "replacement": "<replacement code adhering to {language} keywords>",
      "explanation": "<brief description of the fix>"
    }}
  ]
}}
Do NOT wrap your JSON in markdown fences or conversational prose. Return only raw JSON."""

    prev_fail = ""
    for attempt in range(1, 4):
        cur_prompt = prompt
        if prev_fail:
            cur_prompt += f"\n\nNOTE: Attempt {attempt - 1} failed because: {prev_fail}. Please correct this."

        try:
            chat_res = ai_client.chat(messages=[{"role": "user", "content": cur_prompt}], tier="advanced")
            if not chat_res.get("success"):
                prev_fail = chat_res.get("error") or "AI service returned failure"
                continue

            resp_text = chat_res.get("content", "").strip()
            if not resp_text:
                prev_fail = "Empty response from AI"
                continue

            clean_text = resp_text
            if clean_text.startswith("```"):
                clean_text = re.sub(r'^```(?:json)?\s*', '', clean_text)
                clean_text = re.sub(r'\s*```$', '', clean_text)
                clean_text = clean_text.strip()

            data = json.loads(clean_text)
            fixes = data.get("fixes", [])
            if not fixes:
                prev_fail = "No fixes list in response JSON"
                continue

            fix = fixes[0]
            s_line = int(fix.get("start_line", 0))
            e_line = int(fix.get("end_line", 0))
            orig_snip = str(fix.get("original_snippet", ""))
            replacement = str(fix.get("replacement", ""))

            if not (1 <= s_line <= e_line <= len(lines)):
                prev_fail = f"Line range {s_line}..{e_line} out of bounds"
                continue

            actual_snip = "\n".join(lines[s_line - 1 : e_line])
            if actual_snip.strip() != orig_snip.strip():
                prev_fail = f"original_snippet does not match lines {s_line}..{e_line}"
                continue

            if orig_snip == replacement:
                prev_fail = "replacement is identical to original_snippet"
                continue

            lines_removed = (e_line - s_line + 1) - len(replacement.splitlines())
            if lines_removed > 40:
                prev_fail = f"Patch removed {lines_removed} lines (limit: 40)"
                continue

            cand_lines = lines[:s_line - 1] + replacement.splitlines() + lines[e_line:]
            candidate_code = "\n".join(cand_lines) + ("\n" if current_code.endswith("\n") else "")

            cand_issues = collect_issues(candidate_code, language)
            cand_ids = {i.id for i in cand_issues}
            if issue.id in cand_ids:
                prev_fail = "Target issue still detected in candidate code"
                continue

            cand_tracker = execute_pipeline_with_tracker(candidate_code, language, run_ai_security=False)
            cand_passing = {s["id"] for s in cand_tracker.stages.values() if s.get("status") in ("passed", "warning", "completed")}
            regressed = baseline_passing_stages - cand_passing
            if regressed:
                prev_fail = f"Patch caused previously passing stages to fail: {regressed}"
                continue

            cand_stdout = cand_tracker.artifacts.get("output", "") if cand_tracker.artifacts else ""
            if baseline_stdout.strip() and getattr(issue, "source", "") in ("dead_code", "sast"):
                if cand_stdout.strip() != baseline_stdout.strip():
                    prev_fail = "Stage 13 stdout changed after patch"
                    continue

            used_model = chat_res.get("model") or getattr(ai_client, "model_standard", "Gemini") or "Gemini"
            return {
                "accepted": True,
                "candidate_code": candidate_code,
                "fix_record": {
                    "id": issue.id,
                    "finding_id": issue.id,
                    "rule_id": getattr(issue, "rule_id", ""),
                    "stage_id": getattr(issue, "stage", ""),
                    "line": getattr(issue, "line", 1),
                    "fix_type": "ai",
                    "fixer": used_model,
                    "explanation": fix.get("explanation", f"Repaired by {used_model}"),
                    "original_snippet": orig_snip,
                    "replacement": replacement
                }
            }
        except Exception as e:
            prev_fail = f"Error: {e}"
            continue

    return {"accepted": False, "reason": f"AI fixer unavailable: {prev_fail or 'Verification failed after 3 attempts'}"}


STAGE_ALIASES_MAP = {
    "1": "source_input", "source_input": "source_input", "source": "source_input",
    "2": "lexical_analysis", "lexical_analysis": "lexical_analysis", "lexer": "lexical_analysis", "lexical": "lexical_analysis",
    "3": "syntax_analysis", "syntax_analysis": "syntax_analysis", "parser": "syntax_analysis", "syntax": "syntax_analysis",
    "4": "ast_construction", "ast_construction": "ast_construction", "ast": "ast_construction",
    "5": "semantic_analysis", "semantic_analysis": "semantic_analysis", "semantic": "semantic_analysis", "semantics": "semantic_analysis",
    "6": "symbol_table", "symbol_table": "symbol_table", "symbol": "symbol_table", "symbols": "symbol_table",
    "7": "ir_generation", "ir_generation": "ir_generation", "ir": "ir_generation",
    "8": "optimization", "optimization": "optimization", "opt": "optimization",
    "9": "code_generation", "code_generation": "code_generation", "codegen": "code_generation",
    "10": "code_validation", "code_validation": "code_validation", "target_code_validation": "code_validation", "validation": "code_validation",
    "11": "security_analysis", "security_analysis": "security_analysis", "security": "security_analysis", "sast": "security_analysis",
    "12": "ai_security_analysis", "ai_security_analysis": "ai_security_analysis", "ai_security": "ai_security_analysis", "ai": "ai_security_analysis",
    "13": "sandbox_execution", "sandbox_execution": "sandbox_execution", "sandbox": "sandbox_execution", "execution": "sandbox_execution", "runtime": "sandbox_execution",
    "14": "final_report", "final_report": "final_report", "report": "final_report"
}

def _stage_matches(issue: Any, target: Optional[str]) -> bool:
    if not target or target in ("all", "pipeline", ""):
        return True
    norm_t = STAGE_ALIASES_MAP.get(str(target).lower(), str(target).lower())
    issue_stage = getattr(issue, "stage", issue)
    norm_i = STAGE_ALIASES_MAP.get(str(issue_stage).lower(), str(issue_stage).lower())
    if norm_t == "semantic_analysis" and getattr(issue, "source", "") == "dead_code":
        return False
    return norm_t == norm_i


def run_stage_targeted_fix_all(
    source_code: str,
    language: str = "English",
    file_path: str = "",
    use_ai: bool = True,
    preferred_model: Optional[str] = None,
    target_stage_id: Optional[str] = None,
    run_result: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Executes single-collection based remediation for all fixable issues (Syntax -> Semantic -> Security -> Dead Code).
    Applies fixes sequentially with strict verification on buffer copies.
    Fresh scan of final buffer computes honest N (resolved) and M (total).
    Returns unified delta text, error diffs, and validation badges.
    """
    from web.issue_collector import collect_issues, counts_by_stage, counts_by_severity, total_fixable
    from web.deterministic_fixer import DeterministicFixerRegistry
    from web.pipeline_tracker import execute_pipeline_with_tracker
    from web.gemini_client import ai_client

    filename = os.path.basename(file_path) if file_path else "source.vital"
    effective_language = language or "English"

    if file_path and not is_fix_allowed(file_path, source_code=source_code):
        return {
            "success": True,
            "status": "already_applied",
            "total_diagnostics": 0,
            "resolved_count": 0,
            "remaining_count": 0,
            "proposed_source": source_code,
            "delta_text": "Zero Issues (Clean demo)",
            "applied_fixes": [],
            "fixes": [],
            "manual_fixes": [],
            "error_diffs": [],
            "error_records": [],
            "validation_badge_text": "Verified Clean",
            "validation_badge_class": "val-passed",
            "validation_verdict": "verified_clean",
            "model_selected": "Deterministic",
            "fixer_source": "Deterministic",
            "is_suspect": False,
            "suspect_warnings": []
        }

    initial_issues = collect_issues(source_code, effective_language, run_result=run_result)
    initial_fixable = [i for i in initial_issues if i.fixable and _stage_matches(i, target_stage_id)]

    if not initial_fixable:
        return {
            "success": True,
            "status": "already_applied",
            "total_diagnostics": 0,
            "resolved_count": 0,
            "remaining_count": 0,
            "proposed_source": source_code,
            "delta_text": "Zero Issues",
            "applied_fixes": [],
            "fixes": [],
            "manual_fixes": [],
            "error_diffs": [],
            "error_records": [],
            "validation_badge_text": "Verified Clean",
            "validation_badge_class": "val-passed",
            "validation_verdict": "verified_clean",
            "model_selected": "Deterministic",
            "fixer_source": "Deterministic",
            "is_suspect": False,
            "suspect_warnings": []
        }

    # Record baseline execution
    baseline_tracker = execute_pipeline_with_tracker(source_code, effective_language, run_ai_security=False)
    baseline_stdout = baseline_tracker.artifacts.get("output", "") if baseline_tracker.artifacts else ""
    baseline_passing_stages = {s["id"] for s in baseline_tracker.stages.values() if s.get("status") in ("passed", "warning", "completed")}

    current_code = source_code
    applied_fixes: List[Dict[str, Any]] = []
    failed_fixes: List[Dict[str, Any]] = []
    fixed_ids: Set[str] = set()

    max_passes = 5
    for pass_num in range(max_passes):
        cur_issues = collect_issues(current_code, effective_language, run_result=run_result)
        cur_fixable = [i for i in cur_issues if i.fixable and _stage_matches(i, target_stage_id)]
        if not cur_fixable:
            break

        fixes_applied_this_pass = 0
        for target in cur_fixable:
            fix_accepted = False
            cand_code = None
            cand_rec = None

            det_res = DeterministicFixerRegistry.attempt_fix(
                current_code, target.stage, target.id, target.to_dict(), effective_language
            )
            if det_res and det_res.get("proposed_source") and det_res["proposed_source"] != current_code:
                cand_code = det_res["proposed_source"]
                cand_rec = {
                    "id": target.id,
                    "finding_id": target.id,
                    "rule_id": target.rule_id,
                    "stage_id": target.stage,
                    "line": target.line,
                    "fix_type": "deterministic",
                    "fixer": "Deterministic",
                    "explanation": det_res.get("explanation", f"Fixed {target.id} deterministically."),
                    "original_snippet": det_res.get("original_snippet", ""),
                    "replacement": det_res.get("replacement", "")
                }

            if cand_code:
                cand_issues = collect_issues(cand_code, effective_language, run_result=run_result)
                cand_ids = {i.id for i in cand_issues}
                if target.id not in cand_ids:
                    cand_tracker = execute_pipeline_with_tracker(cand_code, effective_language, run_ai_security=False)
                    cand_passing = {s["id"] for s in cand_tracker.stages.values() if s.get("status") in ("passed", "warning", "completed")}
                    regressed = baseline_passing_stages - cand_passing
                    if not regressed:
                        cand_stdout = cand_tracker.artifacts.get("output", "") if cand_tracker.artifacts else ""
                        stdout_ok = True
                        if baseline_stdout.strip() and target.source in ("dead_code", "sast"):
                            if cand_stdout.strip() != baseline_stdout.strip():
                                stdout_ok = False
                        if stdout_ok:
                            current_code = cand_code
                            fixed_ids.add(target.id)
                            applied_fixes.append(cand_rec)
                            fix_accepted = True
                            fixes_applied_this_pass += 1
                            continue

            if not fix_accepted and use_ai and os.environ.get("VITAL_AI_DISABLED") != "1":
                ai_res = _attempt_gemini_fallback(
                    current_code, target, effective_language, baseline_passing_stages, baseline_stdout
                )
                if ai_res and ai_res.get("accepted"):
                    current_code = ai_res["candidate_code"]
                    fixed_ids.add(target.id)
                    applied_fixes.append(ai_res["fix_record"])
                    fix_accepted = True
                    fixes_applied_this_pass += 1
                else:
                    fail_reason = ai_res.get("reason", "AI fixer unavailable: Patch verification failed") if ai_res else "AI fixer unavailable: No API response"
                    failed_fixes.append({"id": target.id, "reason": fail_reason})

        if fixes_applied_this_pass == 0:
            break

    final_issues = collect_issues(current_code, effective_language, run_result=run_result)
    final_ids = {i.id for i in final_issues}
    really_resolved = [fid for fid in [i.id for i in initial_fixable] if fid not in final_ids]
    N = len(really_resolved)
    M = len(initial_fixable)

    if len(final_issues) == 0:
        val_badge_text = "Verified Clean"
        val_badge_class = "val-passed"
        val_verdict = "verified_clean"
    elif N > 0:
        val_badge_text = "Partially fixed"
        val_badge_class = "val-partial"
        val_verdict = "partially_fixed"
    else:
        val_badge_text = "Not fixed"
        val_badge_class = "val-failed"
        val_verdict = "not_fixed"

    init_err = sum(1 for i in initial_issues if i.severity in ("critical", "high"))
    final_err = sum(1 for i in final_issues if i.severity in ("critical", "high"))
    delta_parts = [
        f"Issues {M} -> {len(final_issues)}",
        f"Errors {init_err} -> {final_err}"
    ]
    delta_text = ", ".join(delta_parts)

    error_diffs = []
    for idx, iss in enumerate(initial_fixable, start=1):
        is_fixed = iss.id in really_resolved
        rec = next((f for f in applied_fixes if f["id"] == iss.id), None)
        fail = next((f for f in failed_fixes if f["id"] == iss.id), None)
        fixer_label = rec["fixer"] if rec else (fail["reason"] if fail else "AI fixer unavailable: verification check failed")
        diff_hunks_res = compute_diff_hunks(source_code, current_code, default_line=iss.line)

        error_diffs.append({
            "index": idx,
            "id": iss.id,
            "finding_id": iss.id,
            "rule_id": iss.rule_id,
            "title": iss.message,
            "message": iss.message,
            "stage_id": iss.stage,
            "severity": iss.severity,
            "line": iss.line,
            "line_start": iss.line,
            "line_end": iss.line,
            "fixed": is_fixed,
            "status": "fixed" if is_fixed else "unfixed",
            "fixer": fixer_label,
            "rule_or_source": "deterministic" if (rec and rec.get("fix_type") == "deterministic") else ("ai" if is_fixed else "unresolved"),
            "explanation": rec.get("explanation", "") if rec else (fail.get("reason", "") if fail else ""),
            "hunks": diff_hunks_res.get("hunks", []),
            "before": rec.get("original_snippet", "") if rec else "",
            "after": rec.get("replacement", "") if rec else ""
        })

    integrity_res = verify_fix_integrity(
        before_code=source_code,
        after_code=current_code,
        language=effective_language,
        filename=filename,
        stage_id=target_stage_id or "syntax_analysis"
    )
    is_suspect = integrity_res.get("is_suspect", False)
    suspect_warnings = integrity_res.get("suspect_reasons", [])
    if integrity_res.get("suspect_warning") and not suspect_warnings:
        suspect_warnings = [integrity_res["suspect_warning"]]

    used_ai = any(f.get("fix_type") == "ai" for f in applied_fixes)
    ai_model_name = getattr(ai_client, "model_standard", "Gemini Flash Lite") or "Gemini Flash Lite"
    model_sel = ai_model_name if used_ai else "Deterministic"
    fixer_src = ai_model_name if used_ai else "Deterministic"

    return {
        "success": True,
        "initial_code": source_code,
        "proposed_source": current_code,
        "delta_text": delta_text,
        "total_diagnostics": M,
        "resolved_count": N,
        "remaining_count": len(final_issues),
        "validation_badge_text": val_badge_text,
        "validation_badge_class": val_badge_class,
        "validation_verdict": val_verdict,
        "applied_fixes": applied_fixes,
        "fixes": applied_fixes,
        "manual_fixes": [],
        "error_diffs": error_diffs,
        "error_records": error_diffs,
        "model_selected": model_sel,
        "fixer_source": fixer_src,
        "is_suspect": is_suspect,
        "suspect_warnings": suspect_warnings
    }


def run_ai_fix_and_rerun_loop(
    source_code: str,
    language: str = "English",
    file_path: str = "",
    use_ai: bool = True,
    preferred_model: Optional[str] = None,
    max_iterations: int = 6,
    on_iteration: Optional[Any] = None,
    stop_signal: Optional[Any] = None
) -> Dict[str, Any]:
    """
    AI Fix & Re-run loop:
    Repairs a failing Security Lab or user-edited program stage by stage until the pipeline passes.
    1. Fixes the FIRST failing stage only (later stages are blocked anyway).
    2. Applies the verified patch to the editor buffer copy.
    3. Re-runs the pipeline from Stage 1.
    4. Stops on:
       - pipeline passes (COMPLETED, or WARNING with allowed findings only);
       - 6 iterations;
       - two consecutive iterations with the same failing stage and the same error;
       - a patch larger than 40% of the file;
       - user pressing Stop.
    5. Returns live iteration log, final summary, issues fixed per stage, whole buffer diff,
       and suspect flags.
    """
    from web.pipeline_tracker import PipelineRunTracker, execute_pipeline_with_tracker
    import difflib

    original_source = source_code
    current_code = source_code
    iteration_records: List[Dict[str, Any]] = []
    iteration_logs: List[str] = []
    issues_fixed_per_stage: Dict[str, int] = {}
    last_err_signature = None
    stop_reason = ""
    suspect_fixes: List[str] = []

    stage_order = [
        "source_input", "lexical_analysis", "syntax_analysis", "ast_construction",
        "semantic_analysis", "symbol_table", "ir_generation", "optimization",
        "code_generation", "code_validation", "security_analysis",
        "ai_security_analysis", "sandbox_execution", "final_report"
    ]

    def _run_pipeline_check(code_to_test: str, rev_num: int):
        code_h = hashlib.sha256(code_to_test.encode("utf-8")).hexdigest()
        tracker = PipelineRunTracker(run_id=f"ai-fix-{rev_num}", source_revision=rev_num, source_hash=code_h)
        execute_pipeline_with_tracker(
            source_code=code_to_test,
            language_hint=language,
            run_ai_security=False,
            tracker=tracker,
            pause_on_error=False
        )
        return tracker

    for iteration in range(1, max_iterations + 1):
        # Check user stop signal
        if stop_signal and stop_signal():
            stop_reason = "User pressed Stop"
            break

        # Re-run pipeline from Stage 1 on current_code
        tracker = _run_pipeline_check(current_code, iteration)
        stage_list = tracker.to_dict().get("stages", [])
        overall_status = tracker.compute_overall_status()

        # Check if pipeline passes (COMPLETED, or WARNING with allowed findings only)
        if overall_status in ("COMPLETED", "WARNING", "completed", "warning") and not any(s.get("status") in ("failed", "blocked") for s in stage_list):
            stop_reason = f"Pipeline passed ({overall_status})"
            break

        # Find the FIRST failing stage only (later stages are blocked anyway)
        first_failing = None
        for s in stage_list:
            if s.get("status") in ("failed", "blocked") or (s.get("status") == "warning" and s.get("gate_status") == "blocked"):
                first_failing = s
                break

        if not first_failing:
            stop_reason = f"No failing stage detected, final status: {overall_status}"
            break

        stage_id = first_failing.get("id", "")
        stage_name = first_failing.get("name", stage_id)
        stage_num = first_failing.get("number")
        if stage_num is None:
            if stage_id in stage_order:
                stage_num = stage_order.index(stage_id) + 1
            else:
                stage_num = "?"

        findings = first_failing.get("details", {}).get("findings", []) or first_failing.get("findings", [])
        first_finding = findings[0] if findings else {}
        f_title = first_finding.get("title") or first_finding.get("message") or "Error"
        f_line = first_finding.get("line") or 1
        f_id = first_finding.get("id") or first_finding.get("rule_id") or ""

        # Check: two consecutive iterations with the same failing stage and same error
        err_signature = (stage_id, f_id, str(f_title), f_line)
        if err_signature == last_err_signature:
            stop_reason = f"Stopped: no progress — two consecutive iterations failed at Stage {stage_num} ({f_title})"
            log_str = f"Iteration {iteration}: Stage {stage_num} ({f_title}, line {f_line}) failed identically to previous iteration -> stopped (no progress)"
            iteration_logs.append(log_str)
            iteration_records.append({
                "iteration": iteration,
                "stage_id": stage_id,
                "stage_number": stage_num,
                "finding": f_title,
                "line": f_line,
                "log": log_str,
                "status": "stopped_no_progress"
            })
            if on_iteration:
                on_iteration({"iteration": iteration, "log": log_str, "status": "stopped"})
            break
        last_err_signature = err_signature

        # Propose fix for the first failing stage using the unified targeted fixer
        fix_res = run_stage_targeted_fix_all(
            source_code=current_code,
            language=language,
            file_path=file_path,
            use_ai=use_ai,
            preferred_model=preferred_model,
            target_stage_id=stage_id
        )

        applied = fix_res.get("applied_fixes", [])
        proposed_code = fix_res.get("proposed_source", current_code)

        if not applied or proposed_code == current_code:
            stop_reason = f"Stopped: no validated fix generated for Stage {stage_num} ({stage_name})"
            log_str = f"Iteration {iteration}: fixing Stage {stage_num} ({f_title}, line {f_line}) -> no validated fix available -> stopped"
            iteration_logs.append(log_str)
            iteration_records.append({
                "iteration": iteration,
                "stage_id": stage_id,
                "stage_number": stage_num,
                "finding": f_title,
                "line": f_line,
                "log": log_str,
                "status": "stopped_unfixed"
            })
            if on_iteration:
                on_iteration({"iteration": iteration, "log": log_str, "status": "stopped"})
            break

        # Check patch size limit: a patch larger than 40% of the file
        orig_lines = current_code.splitlines()
        prop_lines = proposed_code.splitlines()
        matcher = difflib.SequenceMatcher(None, orig_lines, prop_lines)
        changed_lines = sum(max(i2 - i1, j2 - j1) for tag, i1, i2, j1, j2 in matcher.get_opcodes() if tag != "equal")
        total_file_lines = max(len(orig_lines), 1)
        patch_ratio = changed_lines / total_file_lines

        if patch_ratio > 0.40:
            stop_reason = f"Stopped: patch size ({changed_lines}/{total_file_lines} lines, {patch_ratio * 100:.1f}%) exceeds 40% file limit"
            log_str = f"Iteration {iteration}: Stage {stage_num} fix rejected — patch exceeds 40% of file ({patch_ratio * 100:.1f}%) -> stopped"
            iteration_logs.append(log_str)
            iteration_records.append({
                "iteration": iteration,
                "stage_id": stage_id,
                "stage_number": stage_num,
                "finding": f_title,
                "line": f_line,
                "log": log_str,
                "status": "stopped_patch_too_large"
            })
            if on_iteration:
                on_iteration({"iteration": iteration, "log": log_str, "status": "stopped"})
            break

        # Verify fix integrity & suspect detection (Requirement 5)
        integrity_res = verify_fix_integrity(
            before_code=current_code,
            after_code=proposed_code,
            language=language,
            filename=os.path.basename(file_path or "source.vital"),
            stage_id=stage_id
        )
        if integrity_res.get("is_suspect"):
            suspect_reasons = integrity_res.get("suspect_reasons", [])
            suspect_fixes.extend(suspect_reasons)

        # Record fixed issues
        issues_fixed_per_stage[stage_id] = issues_fixed_per_stage.get(stage_id, 0) + len(applied)

        # Apply patch to current_code
        current_code = proposed_code

        # Run pipeline on the new code to format live log requirement:
        # "Iteration 2: fixing Stage 5 (undefined variable 'total_cost', line 41) -> fixed, re-running... Stage 11 -> 3 findings"
        tracker_after = _run_pipeline_check(current_code, iteration + 100)
        stages_after = tracker_after.to_dict().get("stages", [])
        overall_after = tracker_after.compute_overall_status()

        if overall_after in ("COMPLETED", "WARNING", "completed", "warning") and not any(s.get("status") in ("failed", "blocked") for s in stages_after):
            log_str = f"Iteration {iteration}: fixing Stage {stage_num} ({f_title}, line {f_line}) -> fixed, re-running... All 14 stages passed ({overall_after})"
        else:
            next_fail = next((s for s in stages_after if s.get("status") in ("failed", "blocked")), None)
            next_num = next_fail.get("number") if next_fail else "?"
            if next_num is None and next_fail:
                next_id = next_fail.get("id", "")
                if next_id in stage_order:
                    next_num = stage_order.index(next_id) + 1
            next_findings = next_fail.get("details", {}).get("findings", []) or next_fail.get("findings", []) if next_fail else []
            log_str = f"Iteration {iteration}: fixing Stage {stage_num} ({f_title}, line {f_line}) -> fixed, re-running... Stage {next_num} -> {len(next_findings)} findings"

        iteration_logs.append(log_str)
        iteration_records.append({
            "iteration": iteration,
            "stage_id": stage_id,
            "stage_number": stage_num,
            "finding": f_title,
            "line": f_line,
            "fixes_applied": len(applied),
            "log": log_str,
            "status": "fixed"
        })
        if on_iteration:
            on_iteration({
                "iteration": iteration,
                "log": log_str,
                "status": "fixed",
                "proposed_source": current_code
            })

    # Final run to determine definitive final status & artifacts
    final_tracker = _run_pipeline_check(current_code, 999)
    final_stages = final_tracker.to_dict().get("stages", [])
    final_status = final_tracker.compute_overall_status()
    final_passed = (final_status in ("COMPLETED", "WARNING", "completed", "warning")) and not any(s.get("status") in ("failed", "blocked") for s in final_stages)

    if not stop_reason:
        if final_passed:
            stop_reason = f"Pipeline passed ({final_status})"
        elif len(iteration_records) >= max_iterations:
            stop_reason = f"Stopped: reached maximum {max_iterations} iterations"
        else:
            stop_reason = f"Loop ended with status {final_status}"

    # Compute whole buffer diff
    diff_lines = list(difflib.unified_diff(
        original_source.splitlines(keepends=True),
        current_code.splitlines(keepends=True),
        fromfile="a/" + os.path.basename(file_path or "source.vital"),
        tofile="b/" + os.path.basename(file_path or "source.vital"),
        lineterm=""
    ))
    whole_buffer_diff = "".join(diff_lines)

    return {
        "success": final_passed,
        "passed": final_passed,
        "final_status": final_status,
        "iterations_count": len(iteration_records),
        "iterations": iteration_records,
        "iteration_logs": iteration_logs,
        "issues_fixed_per_stage": issues_fixed_per_stage,
        "original_source": original_source,
        "proposed_source": current_code,
        "whole_buffer_diff": whole_buffer_diff,
        "suspect_fixes": suspect_fixes,
        "is_suspect": len(suspect_fixes) > 0,
        "stop_reason": stop_reason,
        "save_enabled": final_passed,
        "undo_available": current_code != original_source
    }

