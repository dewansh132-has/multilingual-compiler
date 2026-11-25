# -*- coding: utf-8 -*-
"""
web/server.py — Flask Web Server and REST API for VITAL IDE

Routes:
  GET  /                  -> Web IDE HTML Interface
  GET  /api/demos         -> List all demo programs (by language and category)
  GET  /api/demo-content  -> Fetch source code of a demo file safely
  POST /api/run           -> Execute source code through the existing compiler pipeline
  GET  /api/health        -> Health check & compiler metadata
"""

import os
import sys
import json
import uuid
import hashlib
import queue
import threading
from flask import g, Flask, render_template, request, jsonify, send_from_directory, Response

from web.compiler_runner import run_pipeline
from web.demo_manager import get_all_demos, get_demo_content, detect_file_language
from web.gemini_client import ai_client, GeminiClient
from web.security_analyzer import security_coordinator
from web.pipeline_tracker import execute_pipeline_with_tracker, PipelineRunTracker, STAGE_DEFINITIONS, run_registry
from web.working_source_manager import working_source_manager

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_env_file = os.path.join(PROJECT_ROOT, ".env")
if os.path.isfile(_env_file):
    try:
        with open(_env_file, "r", encoding="utf-8") as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith("#") and "=" in _line:
                    _k, _v = _line.split("=", 1)
                    _k = _k.strip()
                    _v = _v.strip().strip("'\"")
                    if _k and _k not in os.environ:
                        os.environ[_k] = _v
    except Exception:
        pass
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

app = Flask(
    __name__,
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR,
    static_url_path='/static'
)

from src.source_revision import active_file, normalize_source, source_hash


@app.before_request
def bind_source():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return
    file_id = data.get("file_id", data.get("file_path", data.get("path", "")))
    g.file_token = active_file.set(file_id)
    raw = data.get("source", data.get("source_code", data.get("code")))
    if raw is None:
        return
    if not isinstance(raw, str):
        return jsonify(success=False, error="Source must be text"), 400
    g.revision_id = source_hash(raw)[:12]
    if data.get("revision_id", g.revision_id) != g.revision_id:
        return jsonify(success=False, status="stale_revision", error="Source differs from revision"), 409
    if "source" in data and request.endpoint != "ai_apply_fix":
        data["source_code"] = data["code"] = normalize_source(raw)
    if "file_id" in data:
        data["file_path"] = file_id


@app.teardown_request
def release_source(error):
    token = g.pop("file_token", None)
    if token is not None:
        active_file.reset(token)


# Enable CORS / header protection
@app.after_request
def add_security_headers(response):
    revision = getattr(g, "revision_id", None)
    if revision:
        response.headers["X-Source-Revision"] = revision
        if response.is_json:
            body = response.get_json()
            if isinstance(body, dict):
                body["revision_id"] = revision
                if isinstance(body.get("proposed_source"), str):
                    body["proposed_hash"] = source_hash(body["proposed_source"])
                response.set_data(app.json.dumps(body))
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


@app.route('/')
def index():
    """Renders the main VITAL IDE page."""
    return render_template('index.html')


@app.route('/favicon.ico')
def favicon():
    """Returns empty 204 No Content for favicon requests."""
    return ('', 204)


@app.route('/api/demos', methods=['GET'])
def list_demos():
    """Returns the organized tree of all available demo files."""
    try:
        demos_data = get_all_demos()
        return jsonify({"success": True, "data": demos_data})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/demo-content', methods=['GET'])
def fetch_demo_content():
    """Safely retrieves the content of a specific demo file."""
    path = request.args.get('path', '').strip()
    if not path:
        return jsonify({"success": False, "error": "Query parameter 'path' is required"}), 400

    result = get_demo_content(path)
    if not result.get('success'):
        return jsonify(result), 404
    return jsonify(result)


@app.route('/api/run', methods=['POST'])
def run_code():
    """
    Executes the user-supplied source code through the existing VITAL compiler.
    Expects JSON payload: { "code": str, "language": Optional[str] }
    """
    if not request.is_json:
        return jsonify({
            "success": False,
            "execution_status": "error",
            "status_message": "Request must be JSON",
            "output": "> Error: Invalid request format. Expected JSON body."
        }), 400

    data = request.get_json() or {}
    source_code = data.get('code', '')
    requested_language = data.get('language', '')

    if not source_code or not source_code.strip():
        return jsonify({
            "success": False,
            "execution_status": "empty",
            "status_message": "Empty Source Code",
            "output": "> Error: No source code provided. Please enter or select code to run."
        }), 400

    # Execute through pipeline
    result = run_pipeline(source_code)
    
    # Also attach language detection hint
    detected_lang = detect_file_language(source_code, "")
    result["detected_language"] = detected_lang

    return jsonify(result)


@app.route('/api/save-file', methods=['POST'])
def save_file():
    """
    Saves a corrected program as a separate, regular VITAL file without
    overwriting built-in educational demos.
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    filename = (data.get('filename') or '').strip()
    content = data.get('code') if 'code' in data else data.get('content', '')

    if not filename:
        return jsonify({"success": False, "error": "Filename is required."}), 400

    if '..' in filename or '/' in filename or '\\' in filename:
        return jsonify({"success": False, "error": "Path traversal sequences not allowed in filename."}), 400

    if not filename.endswith('.vital'):
        filename += '.vital'

    safe_filename = os.path.basename(filename)
    if not safe_filename or safe_filename in ('.', '..'):
        return jsonify({"success": False, "error": "Invalid filename."}), 400

    target_dir = os.path.join(PROJECT_ROOT, 'examples', 'saved')
    os.makedirs(target_dir, exist_ok=True)
    target_path = os.path.join(target_dir, safe_filename)
    rel_path = os.path.relpath(target_path, PROJECT_ROOT).replace('\\', '/')

    if 'examples/security_lab' in rel_path.lower():
        return jsonify({"success": False, "error": "Cannot overwrite built-in Security Lab demo."}), 400

    try:
        with open(target_path, 'w', encoding='utf-8') as f:
            f.write(content)
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to save file: {e}"}), 500

    detected_lang = detect_file_language(content, target_path)

    return jsonify({
        "success": True,
        "filename": safe_filename,
        "path": rel_path,
        "language": detected_lang,
        "message": f"Successfully saved {safe_filename} as a separate user file."
    })


# ============================================================================
# PERSISTENT WORKING SOURCE MANAGEMENT (SINGLE SOURCE OF TRUTH)
# ============================================================================

@app.route('/api/working-source', methods=['GET'])
def get_working_source_api():
    """Retrieves the active persisted working source copy for a file."""
    path = request.args.get('path', '').strip()
    if not path:
        return jsonify({"success": False, "error": "Query parameter 'path' is required"}), 400
    res = working_source_manager.get_working_source(path)
    return jsonify(res), (200 if res.get("success") else 404)


@app.route('/api/working-source/save', methods=['POST'])
def save_working_source_api():
    """
    Persists working buffer modifications safely to disk storage in examples/saved/working_copies/.
    Pushes previous version to undo history. Original demo files are never modified.
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    path = data.get('path') or data.get('file_path', '')
    code = data.get('code') if 'code' in data else data.get('content', '')
    expected_revision = data.get('source_revision')
    label = data.get('label', '')

    if not path:
        return jsonify({"success": False, "error": "File path is required"}), 400

    res = working_source_manager.save_working_source(path, code, expected_revision=expected_revision, label=label)
    return jsonify(res), (200 if res.get("success") else 400)


@app.route('/api/working-source/undo', methods=['POST'])
def undo_working_source_api():
    """Reverts working copy to previous snapshot from persistent disk undo stack."""
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    path = data.get('path') or data.get('file_path', '')
    if not path:
        return jsonify({"success": False, "error": "File path is required"}), 400

    res = working_source_manager.undo_working_source(path)
    return jsonify(res), (200 if res.get("success") else 400)


@app.route('/api/working-source/restore-original', methods=['POST'])
def restore_original_source_api():
    """Discards working copy and resets file back to pristine disk demo fixture."""
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    path = data.get('path') or data.get('file_path', '')
    if not path:
        return jsonify({"success": False, "error": "File path is required"}), 400

    res = working_source_manager.restore_original_source(path)
    return jsonify(res), (200 if res.get("success") else 400)


@app.route('/api/ai/fix-all', methods=['POST'])
@app.route('/api/ai/fix-stage', methods=['POST'])
def ai_fix_all():
    """
    Executes stage-specific bulk remediation for all unresolved diagnostics in a stage.
    Employs the shared AIRemediationEngine and Gemini AI model to generate a combined
    validated patch with single-click approval.
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    code = data.get('code') or data.get('source_code', '')
    stage_id = data.get('stage_id', 'syntax_analysis')
    language = data.get('language', 'English')
    file_path = data.get('file_path', '')
    preferred_model = data.get('preferred_model')
    use_ai = bool(data.get('use_ai', True))
    if os.environ.get("VITAL_AI_DISABLED") == "1":
        use_ai = False

    from web.fix_orchestrator import run_stage_targeted_fix_all
    result = run_stage_targeted_fix_all(
        source_code=code,
        language=language,
        file_path=file_path,
        use_ai=use_ai,
        preferred_model=preferred_model,
        target_stage_id=stage_id,
        run_result=data.get('run_result')
    )
    result.update(revision_id=g.revision_id, proposed_hash=source_hash(result.get("proposed_source", code)))
    return jsonify(result), (200 if result.get("success") else 400)


@app.route('/api/ai/fix-all-stages', methods=['POST'])
def ai_fix_all_stages():
    """
    Executes stage-targeted bulk remediation across all 3 groups in strict
    deterministic order: syntax -> semantic -> security (Requirement 2).
    After EACH group, re-runs the Code Health analyzer and records
    {group, issues_before, issues_after}.
    Returns proposed_source, delta_text, groups, and suspect verification results.
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    code = data.get('code') or data.get('source_code', '')
    language = data.get('language', 'English')
    file_path = data.get('file_path', '')
    preferred_model = data.get('preferred_model')
    use_ai = bool(data.get('use_ai', True))
    if os.environ.get("VITAL_AI_DISABLED") == "1":
        use_ai = False

    from web.fix_orchestrator import run_stage_targeted_fix_all
    result = run_stage_targeted_fix_all(
        source_code=code,
        language=language,
        file_path=file_path,
        use_ai=use_ai,
        preferred_model=preferred_model
    )
    return jsonify(result), (200 if result.get("success") else 400)


@app.route('/api/pipeline/ai-fix-and-rerun', methods=['POST'])
def pipeline_ai_fix_and_rerun():
    """
    Executes the stage-by-stage AI Fix & Re-run loop:
    Repairs a failing Security Lab or user-edited program stage by stage until the pipeline passes.
    Stops on: pipeline passes, 6 iterations, two consecutive iterations with same failing stage
    and same error, patch > 40% of file, or user pressing Stop.
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    code = data.get('code') or data.get('source_code', '')
    language = data.get('language', 'English')
    file_path = data.get('file_path') or data.get('file_id', '')
    preferred_model = data.get('preferred_model')
    use_ai = bool(data.get('use_ai', True))
    max_iterations = int(data.get('max_iterations', 6))

    if os.environ.get("VITAL_AI_DISABLED") == "1":
        use_ai = False

    from web.fix_orchestrator import is_fix_allowed, run_ai_fix_and_rerun_loop
    category = data.get('category', '')
    if not is_fix_allowed(file_path, category, source_code=code):
        return jsonify({
            "success": False,
            "error": "AI Fix & Re-run is only permitted for Security Lab scenarios and user-created/edited programs.",
            "final_status": "BLOCKED"
        }), 403

    result = run_ai_fix_and_rerun_loop(
        source_code=code,
        language=language,
        file_path=file_path,
        use_ai=use_ai,
        preferred_model=preferred_model,
        max_iterations=max_iterations
    )
    return jsonify(result)


@app.route('/api/ai/apply-fix', methods=['POST'])
def ai_apply_fix():
    """
    Applies a verified AI correction to the working copy on disk, verifies revision,
    and runs compiler and security validation.
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    if "source" in data:
        from web.fix_orchestrator import apply
        if not all(isinstance(data.get(k), str) for k in ("file_id", "language", "code")):
            return jsonify(success=False, error="Missing file, language or patch text"), 400
        res = apply(data)
        return jsonify(res), 200 if res.get("success") else 409 if res.get("status") == "stale_revision" else 400
    file_path = data.get('file_path') or data.get('path', '')
    code = data.get('code') or data.get('proposed_source', '')
    expected_rev = int(data.get('source_revision') or 1)
    stage_id = data.get('stage_id', 'syntax_analysis')
    language = data.get('language', 'English')
    finding_id = data.get('finding_id', '')

    from web.ai_remediation_engine import remediation_engine
    res = remediation_engine.apply_and_verify_fix(
        file_path=file_path,
        proposed_source=code,
        expected_revision=expected_rev,
        stage_id=stage_id,
        language=language,
        finding_id=finding_id
    )
    # 200 for success or already_applied; 409 for stale revision
    if res.get("status") == "already_applied":
        return jsonify(res), 200
    if res.get("status") == "stale_revision":
        return jsonify(res), 409
    return jsonify(res), (200 if res.get("success") else 400)


@app.route('/api/ai/benchmark', methods=['GET', 'POST'])
def ai_benchmark():
    """
    Executes a real-time live benchmark comparing Gemini fast vs advanced models.
    """
    from web.gemini_client import ai_client
    is_online, _, _ = ai_client.check_health()
    if not is_online:
        return jsonify({"success": False, "error": "Gemini AI is currently offline."}), 503

    benchmark_prompt = [
        {"role": "system", "content": "You are a VITAL compiler assistant. Output JSON with key status and value ok."},
        {"role": "user", "content": "Benchmark test. Output JSON: {\"status\": \"ok\"}"}
    ]

    models_to_benchmark = [ai_client.model_fast, ai_client.model_advanced]
    results = {}
    is_same_model = (ai_client.model_fast == ai_client.model_advanced)

    for m in models_to_benchmark:
        if m in results:
            continue
        t0 = time.time()
        res = ai_client.chat(messages=benchmark_prompt, model=m, max_tokens=20, timeout=50.0)
        tot_ms = round((time.time() - t0) * 1000, 2)
        results[m] = {
            "success": res.get("success", False),
            "model_load_time_ms": res.get("model_load_time_ms", 0.0),
            "inference_time_ms": res.get("inference_time_ms", 0.0),
            "total_time_ms": tot_ms,
            "tokens_per_second": res.get("tokens_per_second", 0.0),
            "tokens_generated": res.get("tokens_generated", 0)
        }

    resp_data = {
        "success": True,
        "hardware": ai_client.get_hardware_status(),
        "benchmark": results
    }
    if is_same_model:
        resp_data["note"] = f"Both fast and advanced tiers are configured to use the same model ('{ai_client.model_fast}')."

    return jsonify(resp_data)



@app.route('/api/health', methods=['GET'])
def health_check():
    """Health status and metadata."""
    return jsonify({
        "status": "healthy",
        "service": "VITAL Multilingual Compiler Web IDE",
        "version": "2.0.0",
        "supported_languages": [
            "English", "Hindi", "Telugu", "Bengali", "Marathi", "Nepali"
        ],
        "backend": "Existing Python Compiler Engine (src.main.Compiler)"
    })




# ============================================================================
# SECURITY & AI AGENT ENDPOINTS
# ============================================================================

@app.route('/api/ai/status', methods=['GET'])
def ai_status():
    """Returns the live status of the Gemini AI service, resolved model, and honest reason."""
    force = request.args.get('refresh', '').lower() in ('1', 'true')
    healthy, msg, details = ai_client.check_health(force_refresh=force)
    return jsonify({
        "ok": bool(healthy),
        "model": getattr(ai_client, "resolved_model", ai_client.model_name),
        "reason": msg,
        "details": details
    })


@app.route('/api/security/status', methods=['GET'])
def security_status():
    """Returns Gemini AI service availability and configuration."""
    is_online, msg, details = ai_client.check_health(force_refresh=True)
    resolved_m = getattr(ai_client, "resolved_model", ai_client.model_name)
    return jsonify({
        "success": True,
        "ai_online": is_online,
        "ollama_online": is_online,  # Deprecated alias for backwards compatibility
        "ai_healthy": is_online,
        "ollama_healthy": is_online,  # Deprecated alias for backwards compatibility
        "model": resolved_m,
        "message": msg,
        "details": details,
        "config": ai_client.get_config(),
        "rules_enabled": [
            "lexical",
            "parser",
            "ast",
            "execution_boundary"
        ],
        "enabled_check_categories": [
            "Lexical Homoglyph & Literal Injection",
            "Parser Delimiter & Structural Scope",
            "Python Intermediate Representation (AST Visitor)",
            "Execution Boundary & Resource Bounds"
        ]
    })


@app.route('/api/security/scan', methods=['POST'])
def security_scan():
    """
    Executes multi-stage static security scan and optional Gemini AI investigation.
    Strictly read-only; never mutates source code.
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    code = data.get('code') or data.get('source_code', '')
    ir_code = data.get('ir_code', '')
    language = data.get('language', 'English')
    use_ai = data.get('use_ai', True)

    if not code or not code.strip():
        return jsonify({
            "success": True,
            "overall_risk_score": 0,
            "overall_summary": "No issues detected by enabled checks.",
            "summary": "No issues detected by enabled checks.",
            "total_findings": 0,
            "findings": []
        })

    syntax_blocked = data.get('syntax_blocked', None)

    result = security_coordinator.run_full_scan(
        source_code=code,
        ir_code=ir_code,
        language=language,
        use_ai_enrichment=use_ai,
        syntax_blocked=syntax_blocked
    )
    try:
        content_hash = source_hash(code)[:8]
        result['content_hash'] = content_hash
        fname = os.path.basename(data.get('file_path') or "source.vital")
        print(f"[Stage 11] scanning {fname} @ {content_hash} -> {len(result.get('findings', []))} issues found")
    except Exception:
        pass
    return jsonify(result)


@app.route('/api/security/suggest-fix', methods=['POST'])
def security_suggest_fix():
    """
    Generates a proposed minimal correction diff for a specific security finding
    or compiler diagnostic. Fast deterministic rules run first for instant remediation,
    while compiler errors or AI requests route to the stage-aware AIRemediationEngine.
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    code = data.get('code') or data.get('source_code', '')
    finding_id = data.get('finding_id', '')
    finding_data = data.get('finding', {})
    stage_id = data.get('stage_id') or finding_data.get('stage_id', '')
    language = data.get('language', 'English')
    prefer_deterministic = data.get('prefer_deterministic', True)
    request_ai = data.get('request_ai', False)

    if "source" in data:
        from web.ai_remediation_engine import remediation_engine
        return jsonify(remediation_engine.generate_fix_all(
            source_code=code, stage_id=stage_id, diagnostics=[finding_data], target=finding_data,
            language=language, file_path=data.get("file_id", ""),
            use_ai=request_ai and os.environ.get("VITAL_AI_DISABLED") != "1"))
    compiler_stages = {
        "source_input", "lexical_analysis", "syntax_analysis", "ast_construction",
        "semantic_analysis", "symbol_table", "ir_generation", "optimization",
        "code_generation", "code_validation", "parser"
    }

    preferred_model = data.get('preferred_model')

    # Fast deterministic rules run first for instant remediation
    if prefer_deterministic and not request_ai:
        det_result = security_coordinator.suggest_fix_for_finding(
            source_code=code,
            finding_id=finding_id,
            finding_data=finding_data,
            language=language,
            prefer_deterministic=True,
            request_ai=False
        )
        if det_result.get("success") and det_result.get("is_deterministic"):
            return jsonify(det_result)

    # If it is explicitly a compiler stage error (or parser finding), route to remediation_engine
    if stage_id in compiler_stages or str(finding_id).startswith(("SYN-", "SEC-PAR-", "SEM-", "SEC-SEM-", "IR-", "OPT-")):
        from web.ai_remediation_engine import remediation_engine
        fix_result = remediation_engine.generate_fix(
            source_code=code,
            stage_id=stage_id or "syntax_analysis",
            finding_id=finding_id,
            finding_data=finding_data,
            language=language,
            preferred_model=preferred_model
        )
        if fix_result.get("success"):
            return jsonify(fix_result)

    # Standard security lab finding — route to security_coordinator
    fix_result = security_coordinator.suggest_fix_for_finding(
        source_code=code,
        finding_id=finding_id,
        finding_data=finding_data,
        language=language,
        prefer_deterministic=prefer_deterministic,
        request_ai=request_ai
    )
    return jsonify(fix_result)


@app.route('/api/ai/suggest-fix', methods=['POST'])
def ai_suggest_fix():
    """
    Generates a proposed minimal correction diff for a specific compiler stage diagnostic or finding.
    Employs the shared stage-aware AIRemediationEngine powered by Gemini AI.
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    code = data.get('code') or data.get('source_code', '')
    finding_id = data.get('finding_id', '')
    finding_data = data.get('finding', {})
    stage_id = data.get('stage_id') or finding_data.get('stage_id', 'syntax_analysis')
    language = data.get('language', 'English')
    source_revision = int(data.get('source_revision', 1))
    file_path = data.get('file_path', '')

    preferred_model = data.get('preferred_model')

    from web.ai_remediation_engine import remediation_engine
    fix_result = remediation_engine.generate_fix(
        source_code=code,
        stage_id=stage_id,
        finding_id=finding_id,
        finding_data=finding_data,
        language=language,
        source_revision=source_revision,
        file_path=file_path,
        preferred_model=preferred_model
    )
    return jsonify(fix_result)


@app.route('/api/security/refine-fix', methods=['POST'])
def security_refine_fix():
    """
    Asynchronously refines an existing deterministic proposal using Gemini AI.
    If Gemini is offline or times out, safely retains the deterministic proposal.
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    code = data.get('code') or data.get('source_code', '')
    finding_id = data.get('finding_id', '')
    finding_data = data.get('finding', {})
    current_fix = data.get('current_fix', {})
    language = data.get('language', 'English')

    refined = security_coordinator.refine_fix_with_ai(
        source_code=code,
        finding_id=finding_id,
        finding_data=finding_data,
        current_fix=current_fix,
        language=language
    )
    return jsonify(refined)


@app.route('/api/security/verify-repair', methods=['POST'])
def security_verify_repair():
    """
    Re-analyzes code before and after a proposed repair to confirm whether
    the finding was genuinely resolved, whether syntax/semantics pass,
    and returns an updated risk score and pedagogical verification report.
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    original_code = data.get('original_code') or data.get('original_source', '')
    repaired_code = data.get('repaired_code') or data.get('repaired_source', '')
    language = data.get('language', 'English')
    target_finding_id = data.get('target_finding_id')

    report = security_coordinator.verify_repair(
        original_source=original_code,
        repaired_source=repaired_code,
        language=language,
        target_finding_id=target_finding_id
    )
    return jsonify(report)


@app.route('/api/security-lab/demos', methods=['GET'])
def list_security_lab_demos():
    """Returns the registered Security Lab demos and educational metadata."""
    try:
        from web.security_lab_registry import get_all_security_lab_demos
        demos = get_all_security_lab_demos()
        return jsonify({"success": True, "count": len(demos), "demos": demos})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================================
# LIVE COMPILER PIPELINE PROGRESS ENDPOINTS
# ============================================================================

@app.route('/api/pipeline/stages', methods=['GET'])
def pipeline_stages():
    """Returns the ordered metadata of actual compiler pipeline stages."""
    return jsonify({
        "success": True,
        "stages": STAGE_DEFINITIONS,
        "total_stages": len(STAGE_DEFINITIONS)
    })


@app.route('/api/pipeline/run', methods=['POST'])
def pipeline_run_sync():
    """
    Synchronously runs the complete compilation & security pipeline with stage tracking.
    Returns the complete stage-by-stage execution trace and final compiler artifacts.
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    code = data.get('code') or data.get('source_code', '')
    language = data.get('language', '')
    use_ai_security = data.get('use_ai_security', True)
    pause_on_error = data.get('pause_on_error', False)
    run_id = data.get('run_id') or str(uuid.uuid4())
    session_id = data.get('session_id') or request.headers.get('X-Session-ID') or request.remote_addr or "default"
    source_revision = int(data.get('source_revision', 1))
    resume_from = data.get('resume_from')
    security_override = bool(data.get('override') or data.get('security_override'))
    code_hash = hashlib.sha256((code or "").encode("utf-8")).hexdigest()

    tracker = PipelineRunTracker(run_id=run_id, source_revision=source_revision, source_hash=code_hash, session_id=session_id)
    run_registry.register_run(session_id, tracker)
    execute_pipeline_with_tracker(
        source_code=code,
        language_hint=language,
        run_ai_security=use_ai_security,
        tracker=tracker,
        pause_on_error=pause_on_error,
        resume_from=resume_from,
        source_revision=source_revision,
        security_override=security_override,
        session_id=session_id
    )

    resp_data = tracker.to_dict()
    resp_data["run_id"] = tracker.run_id
    resp_data["source_hash"] = tracker.source_hash
    return jsonify(resp_data)


@app.route('/api/pipeline/retry-optimization', methods=['POST'])
def pipeline_retry_optimization():
    """
    Executes or retries IR Optimization on current valid IR from source code.
    Guarantees optimization execution without stale IR or skipped states.
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    code = data.get('code') or data.get('source_code', '')
    language = data.get('language', '')
    use_ai = data.get('use_ai', False)

    if not code or not code.strip():
        return jsonify({"success": False, "error": "Source code is empty"}), 400

    try:
        from web.pipeline_tracker import Compiler, RULES_FILE, TESTS_DIR
        from web.ir_optimizer import IROptimizer

        comp = Compiler(RULES_FILE)
        comp.load_rules()
        ir_code = comp.transpile(code)
        if not ir_code or not ir_code.strip():
            return jsonify({
                "success": False,
                "error": "Failed to generate Intermediate Representation for optimization."
            }), 400

        opt_res = IROptimizer.optimize(ir_code, use_ai=use_ai)
        if opt_res.get("success"):
            opt_ir = opt_res.get("optimized_ir", ir_code)
            with open(os.path.join(TESTS_DIR, "ir.txt"), "w", encoding="utf-8") as irf:
                irf.write(opt_ir)

        return jsonify({
            "success": opt_res.get("success", False),
            "stage_id": "optimization",
            "stage": "8. Optimization",
            "status": "completed" if opt_res.get("success") else "failed",
            "summary": opt_res.get("summary", "Optimization completed."),
            "details": opt_res,
            "optimized_ir": opt_res.get("optimized_ir", ir_code)
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Optimization execution error: {e}"
        }), 500


@app.route('/api/pipeline/stream', methods=['POST'])
def pipeline_run_stream():
    """
    Executes the pipeline while streaming Server-Sent Events (SSE) in real time
    as each genuine backend compiler stage starts, updates, and completes.
    Carries run_id and source_hash on all messages (Requirement 1).
    Cancels any previous active run for this session first (Requirement 3).
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    code = data.get('code') or data.get('source_code', '')
    language = data.get('language', '')
    use_ai_security = data.get('use_ai_security', True)
    pause_on_error = data.get('pause_on_error', False)
    run_id = data.get('run_id') or str(uuid.uuid4())
    session_id = data.get('session_id') or request.headers.get('X-Session-ID') or request.remote_addr or "default"
    source_revision = int(data.get('source_revision', 1))
    resume_from = data.get('resume_from')
    security_override = bool(data.get('override') or data.get('security_override'))
    code_hash = hashlib.sha256((code or "").encode("utf-8")).hexdigest()

    tracker = PipelineRunTracker(run_id=run_id, source_revision=source_revision, source_hash=code_hash, session_id=session_id)
    run_registry.register_run(session_id, tracker)
    revision_id = source_hash(code)[:12]

    def generate_events():
        # Start worker thread
        worker_thread = threading.Thread(
            target=execute_pipeline_with_tracker,
            kwargs={
                "source_code": code,
                "language_hint": language,
                "run_ai_security": use_ai_security,
                "tracker": tracker,
                "pacing_ms": 35.0,
                "pause_on_error": pause_on_error,
                "pause_on_findings": bool(data.get("pause_on_findings")),
                "manual_stages": data.get("manual_stages", []),
                "resume_from": resume_from,
                "source_revision": source_revision,
                "security_override": security_override,
                "session_id": session_id
            },
            daemon=True
        )
        worker_thread.start()

        # Yield events from queue until finished
        terminal_emitted = False
        while True:
            try:
                event = tracker.event_queue.get(timeout=0.1)
                event["revision_id"] = revision_id
                event["run_id"] = tracker.run_id
                event["source_hash"] = tracker.source_hash
                try:
                    data_str = json.dumps(event)
                except Exception as json_err:
                    def _json_safe(obj):
                        if isinstance(obj, (str, int, float, bool, type(None))):
                            return obj
                        if isinstance(obj, dict):
                            return {str(k): _json_safe(v) for k, v in obj.items()}
                        if isinstance(obj, (list, tuple, set)):
                            return [_json_safe(x) for x in obj]
                        return str(obj)
                    safe_event = _json_safe(event)
                    data_str = json.dumps(safe_event)

                yield f"data: {data_str}\n\n"
                if event.get("event") in ("pipeline_finish", "pipeline_paused"):
                    terminal_emitted = True
                    break
            except queue.Empty:
                if tracker.is_finished and tracker.event_queue.empty():
                    break
                if not worker_thread.is_alive() and tracker.event_queue.empty():
                    break
                continue

        # If loop terminated without emitting a terminal event, emit one now
        if not terminal_emitted:
            final_status = getattr(tracker, "final_status", "completed") or "completed"
            is_complete = final_status in ("completed", "warning", "executed_with_override")
            fallback_payload = {
                "event": "pipeline_finish",
                "run_id": tracker.run_id,
                "revision_id": revision_id,
                "source_hash": tracker.source_hash,
                "status": final_status,
                "overall_status": final_status,
                "summary": f"Pipeline finished with status '{final_status}'.",
                "artifacts": getattr(tracker, "artifacts", {}) or {},
                "stages": [dict(s) for s in tracker.stages.values()],
                "counts_by_stage": dict(getattr(tracker, "counts_by_stage", {})),
                "counts_by_severity": dict(getattr(tracker, "counts_by_severity", {})),
                "total_fixable": getattr(tracker, "total_fixable", 0),
                "completed_count": tracker.completed_stages_count,
                "progress_pct": 100 if is_complete else round((tracker.completed_stages_count / max(1, len(tracker.applicable_stage_ids))) * 100)
            }
            yield f"data: {json.dumps(fallback_payload)}\n\n"

    return Response(
        generate_events(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )


@app.route('/api/pipeline/cancel', methods=['POST'])
def pipeline_cancel():
    """
    Cancels an active pipeline execution (Requirement 2).
    Stops the orchestrator at the next stage boundary and marks remaining stages skipped (reason: cancelled).
    Terminates running sandbox processes immediately.
    """
    data = request.get_json(silent=True) or {}
    run_id = data.get("run_id")
    session_id = data.get("session_id") or request.headers.get("X-Session-ID")
    cancelled = False

    if run_id:
        cancelled = run_registry.cancel_run(run_id, reason="cancelled by user")

    if not cancelled and session_id:
        with run_registry.lock:
            active_t = run_registry.active_session_runs.get(session_id)
            if active_t and not active_t.is_finished:
                active_t.cancel(reason="cancelled by user")
                cancelled = True

    return jsonify({"success": True, "cancelled": cancelled, "run_id": run_id})


@app.route('/api/runs/<run_id>', methods=['GET'])
def get_run_details(run_id):
    """
    Retrieves the full stage table and metadata for a run (Requirement 5).
    Allows the UI to recover cleanly after a page refresh.
    """
    run_data = run_registry.get_run(run_id)
    if not run_data:
        return jsonify({"success": False, "error": f"Run '{run_id}' not found"}), 404

    stages_list = run_data.get("stages", [])
    return jsonify({
        "success": True,
        "run_id": run_data.get("run_id"),
        "source_hash": run_data.get("source_hash"),
        "source_revision": run_data.get("source_revision"),
        "status": run_data.get("status"),
        "overall_status": run_data.get("overall_status"),
        "header_message": run_data.get("header_message"),
        "progress_pct": run_data.get("progress_pct"),
        "completed_count": run_data.get("completed_count"),
        "applicable_count": run_data.get("applicable_count", 14),
        "elapsed_ms": run_data.get("elapsed_ms"),
        "stages": stages_list,
        "stage_table": stages_list,
        "artifacts": run_data.get("artifacts", {}),
        "issues": run_data.get("issues", []),
        "counts_by_stage": dict(run_data.get("counts_by_stage", {})),
        "counts_by_severity": dict(run_data.get("counts_by_severity", {})),
        "total_fixable": run_data.get("total_fixable", 0),
        "is_finished": run_data.get("is_finished", True),
        "is_cancelled": run_data.get("is_cancelled", False)
    })


@app.route('/api/pipeline/generate-report', methods=['POST'])
def pipeline_generate_report():
    """
    Explicit completion gate for the Final Report stage:
    1. Verifies that the source code matches the compiled revision.
    2. Verifies that all required compilation stages have passed.
    3. Assembles genuine compiler artifacts (output, pipeline report, lexer, parser, ast, ir, symbol table).
    4. Marks the Final Report stage completed and returns the complete artifacts.
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    code = data.get('code') or data.get('source_code', '')
    language = data.get('language', '')
    run_id = data.get('run_id') or str(uuid.uuid4())
    session_id = data.get('session_id') or request.headers.get('X-Session-ID') or request.remote_addr or "default"

    if not code or not code.strip():
        return jsonify({"success": False, "error": "Source code is empty"}), 400

    source_revision = int(data.get('source_revision', 1))
    code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()

    # Execute full pipeline with auto_generate_report to assemble genuine artifacts
    tracker = PipelineRunTracker(run_id=run_id, source_revision=source_revision, source_hash=code_hash, session_id=session_id)
    run_registry.register_run(session_id, tracker)
    execute_pipeline_with_tracker(
        source_code=code,
        language_hint=language,
        run_ai_security=False,
        tracker=tracker,
        pause_on_error=False,
        source_revision=source_revision,
        session_id=session_id
    )

    t_dict = tracker.to_dict()
    allow_incomplete = bool(data.get("allow_incomplete") or data.get("force") or request.args.get("allow_incomplete"))

    # Backend-enforced completion guard for mandatory stages (1-10)
    mandatory_stages = [
        ("source_input", "Source Input"),
        ("lexical_analysis", "Lexical Analysis"),
        ("syntax_analysis", "Syntax Analysis"),
        ("ast_construction", "AST Construction"),
        ("semantic_analysis", "Semantic Analysis"),
        ("symbol_table", "Symbol Table"),
        ("ir_generation", "Intermediate Representation (IR)"),
        ("optimization", "Optimization"),
        ("code_generation", "Code Generation"),
        ("code_validation", "Target Code Validation")
    ]
    failed_mandatory = []
    for m_id, m_name in mandatory_stages:
        st = next((s for s in t_dict["stages"] if s["id"] == m_id), None)
        st_status = st.get("status", "missing") if st else "missing"
        if not st or st_status not in ("completed", "passed", "warning"):
            failed_mandatory.append((m_id, m_name, st_status, st.get("details", {}) if st else {}))

    if failed_mandatory and not allow_incomplete:
        m_id, m_name, st_status, details = failed_mandatory[0]
        return jsonify({
            "success": False,
            "error": f"Cannot generate Final Report: Mandatory stage '{m_name}' did not complete successfully (Status: {st_status.upper()}). {m_name} stage failed.",
            "blocked_stage": m_id,
            "stage_status": st_status,
            "details": details
        }), 400

    is_incomplete = bool(failed_mandatory) or tracker.stages.get("sandbox_execution", {}).get("status") not in ("passed", "completed")
    if not is_incomplete:
        tracker.complete_final_report()

    result = tracker.to_dict()
    return jsonify({
        "success": True,
        "run_id": result.get("run_id"),
        "source_hash": tracker.source_hash,
        "status": result.get("status"),
        "artifacts": result.get("artifacts"),
        "elapsed_ms": result.get("elapsed_ms"),
        "stages": result.get("stages"),
        "source_revision": source_revision,
        "is_incomplete": is_incomplete,
        "complete": not is_incomplete,
        "report": (result.get("artifacts") or {}).get("aggregated_log", "")
    })


@app.route('/api/pipeline/override-run', methods=['POST'])
def pipeline_override_run():
    """
    Explicit educational override endpoint:
    Executes only Stage 13 (sandbox_execution) when blocked by Stage 11 or 12.
    Tags the run override=True and stamps output with [EXECUTED WITH SECURITY OVERRIDE].
    Does NOT mark stage 11 or 12 as passed.
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    code = data.get('code') or data.get('source_code', '')
    language = data.get('language', '')
    run_id = data.get('run_id') or str(uuid.uuid4())
    session_id = data.get('session_id') or request.headers.get('X-Session-ID') or request.remote_addr or "default"
    source_revision = int(data.get('source_revision', 1))
    code_hash = hashlib.sha256((code or "").encode("utf-8")).hexdigest()

    tracker = PipelineRunTracker(run_id=run_id, source_revision=source_revision, source_hash=code_hash, session_id=session_id)
    run_registry.register_run(session_id, tracker)
    execute_pipeline_with_tracker(
        source_code=code,
        language_hint=language,
        run_ai_security=False,
        tracker=tracker,
        pause_on_error=False,
        source_revision=source_revision,
        security_override=True,
        session_id=session_id
    )
    res_dict = tracker.to_dict()
    res_dict["run_id"] = tracker.run_id
    res_dict["source_hash"] = tracker.source_hash
    return jsonify(res_dict)


@app.route('/api/pipeline/retry-stage', methods=['POST'])
def pipeline_retry_stage():
    """Retries an individual pipeline stage (such as stage 12 AI security analysis)."""
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    code = data.get('code') or data.get('source_code', '')
    language = data.get('language', '')
    run_id = data.get('run_id') or str(uuid.uuid4())
    session_id = data.get('session_id') or request.headers.get('X-Session-ID') or request.remote_addr or "default"
    source_revision = int(data.get('source_revision', 1))
    code_hash = hashlib.sha256((code or "").encode("utf-8")).hexdigest()

    tracker = PipelineRunTracker(run_id=run_id, source_revision=source_revision, source_hash=code_hash, session_id=session_id)
    run_registry.register_run(session_id, tracker)
    execute_pipeline_with_tracker(
        source_code=code,
        language_hint=language,
        run_ai_security=True,
        tracker=tracker,
        pause_on_error=False,
        source_revision=source_revision,
        session_id=session_id
    )
    res_dict = tracker.to_dict()
    res_dict["run_id"] = tracker.run_id
    res_dict["source_hash"] = tracker.source_hash
    return jsonify(res_dict)


@app.route('/api/health/analyze', methods=['POST'])
def health_analyze():
    """
    Pre-run Code Health analysis endpoint.
    Accepts { source, language, filename } (or code as fallback for source).
    Returns complete Code Health JSON report.
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    source = data.get("source") or data.get("code") or ""
    language = data.get("language") or ""
    filename = data.get("filename") or ""

    from web.code_health import analyze_health
    result = analyze_health(source, language=language, filename=filename)
    return jsonify(result)


@app.route('/api/issues/collect', methods=['POST'])
def issues_collect():
    """
    Unified canonical issues collection endpoint.
    Accepts { source, language, filename, run_id (optional) }.
    Returns {
        success: True,
        source_hash: str,
        total_count: int,
        fixable_count: int,
        issues: [...],
        counts_by_stage: {...},
        counts_by_severity: {...},
        breakdown: {...}
    }
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    source = data.get("source") or data.get("code") or ""
    language = data.get("language") or ""
    run_id = data.get("run_id")

    run_result = None
    if run_id:
        run_result = run_registry.get(run_id)

    from web.issue_collector import collect_issues, counts_by_stage, counts_by_severity, total_fixable
    canonical_issues = collect_issues(source, language=language, run_result=run_result)

    src_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
    fixable_cnt = total_fixable(canonical_issues)
    stg_counts = counts_by_stage(canonical_issues)
    sev_counts = counts_by_severity(canonical_issues)

    breakdown = {
        "security": sum(1 for i in canonical_issues if i.source in ("sast", "ai")),
        "dead_code": sum(1 for i in canonical_issues if i.source == "dead_code"),
        "lexer": sum(1 for i in canonical_issues if i.source == "lexer"),
        "syntax": sum(1 for i in canonical_issues if i.source == "parser"),
        "semantic": sum(1 for i in canonical_issues if i.source == "semantic"),
        "runtime": sum(1 for i in canonical_issues if i.source == "runtime"),
    }
    parts = []
    if breakdown["security"]: parts.append(f"{breakdown['security']} security")
    if breakdown["dead_code"]: parts.append(f"{breakdown['dead_code']} dead code")
    if breakdown["lexer"]: parts.append(f"{breakdown['lexer']} lexer")
    if breakdown["syntax"]: parts.append(f"{breakdown['syntax']} syntax")
    if breakdown["semantic"]: parts.append(f"{breakdown['semantic']} semantic")
    if breakdown["runtime"]: parts.append(f"{breakdown['runtime']} runtime")
    breakdown_text = f"{len(canonical_issues)} = {' + '.join(parts)}" if parts else "0 issues"
    breakdown["summary"] = breakdown_text

    return jsonify({
        "success": True,
        "source_hash": src_hash,
        "total_count": len(canonical_issues),
        "fixable_count": fixable_cnt,
        "issues": [i.to_dict() for i in canonical_issues],
        "counts_by_stage": stg_counts,
        "counts_by_severity": sev_counts,
        "breakdown": breakdown
    })


@app.route('/api/pipeline/reset', methods=['POST'])
def pipeline_reset():
    """
    Clears backend pipeline logs and temporary compiler artifacts on reset.
    """
    from web.pipeline_tracker import TESTS_DIR
    for f_name in ("ir.txt", "output.txt", "parser_log.txt", "lexer_log.txt", "ast_log.txt", "opt_ir.txt", "symbol_table.txt", "semantic_log.txt"):
        p = os.path.join(TESTS_DIR, f_name)
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass
    return jsonify({"success": True, "message": "Pipeline artifacts and state reset."})


@app.route('/api/working-copy/clear-all', methods=['POST'])
def clear_all_working_copies_endpoint():
    """Backend endpoint to delete all saved working copies."""
    from web.working_source_manager import working_source_manager
    res = working_source_manager.clear_all_working_copies()
    return jsonify(res)


def create_app():
    return app


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    print(f"\n=======================================================")
    print(f"  VITAL Multilingual IDE Server starting on http://localhost:{port}")
    print(f"=======================================================\n")
    app.run(host='0.0.0.0', port=port, debug=False)
