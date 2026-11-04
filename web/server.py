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
import queue
import threading
from flask import Flask, render_template, request, jsonify, send_from_directory, Response

from web.compiler_runner import run_pipeline
from web.demo_manager import get_all_demos, get_demo_content, detect_file_language
from web.ai_assistant import ai_assistant
from web.ollama_client import ollama_client
from web.security_analyzer import security_coordinator
from web.pipeline_tracker import execute_pipeline_with_tracker, PipelineRunTracker, STAGE_DEFINITIONS
from web.working_source_manager import working_source_manager

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

app = Flask(
    __name__,
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR,
    static_url_path='/static'
)

# Enable CORS / header protection
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


@app.route('/')
def index():
    """Renders the main VITAL IDE page."""
    return render_template('index.html')


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
def ai_fix_all():
    """
    Executes stage-specific bulk remediation for all unresolved diagnostics in a stage.
    Employs the shared AIRemediationEngine and local Ollama model to generate a combined
    validated patch with single-click approval.
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    code = data.get('code') or data.get('source_code', '')
    stage_id = data.get('stage_id', 'syntax_analysis')
    diagnostics = data.get('diagnostics', [])
    language = data.get('language', 'English')
    source_revision = int(data.get('source_revision', 1))
    file_path = data.get('file_path', '')
    preferred_model = data.get('preferred_model')

    from web.ai_remediation_engine import remediation_engine
    result = remediation_engine.generate_fix_all(
        source_code=code,
        stage_id=stage_id,
        diagnostics=diagnostics,
        language=language,
        source_revision=source_revision,
        file_path=file_path,
        preferred_model=preferred_model
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
    return jsonify(res), (200 if res.get("success") else 400)


@app.route('/api/ai/benchmark', methods=['GET', 'POST'])
def ai_benchmark():
    """
    Executes a real-time live benchmark comparing qwen2.5-coder:3b vs qwen2.5-coder:7b-instruct
    on the current machine (Intel Core i5-11300H, 16 GB RAM).
    """
    from web.ollama_client import ollama_client
    is_online, _, _ = ollama_client.check_health()
    if not is_online:
        return jsonify({"success": False, "error": "Ollama is currently offline."}), 503

    benchmark_prompt = [
        {"role": "system", "content": "You are a VITAL compiler assistant. Output JSON with key status and value ok."},
        {"role": "user", "content": "Benchmark test. Output JSON: {\"status\": \"ok\"}"}
    ]

    results = {}
    for m in [ollama_client.model_fast, ollama_client.model_advanced]:
        t0 = time.time()
        res = ollama_client.chat(messages=benchmark_prompt, model=m, max_tokens=20, timeout=50.0)
        tot_ms = round((time.time() - t0) * 1000, 2)
        results[m] = {
            "success": res.get("success", False),
            "model_load_time_ms": res.get("model_load_time_ms", 0.0),
            "inference_time_ms": res.get("inference_time_ms", 0.0),
            "total_time_ms": tot_ms,
            "tokens_per_second": res.get("tokens_per_second", 0.0),
            "tokens_generated": res.get("tokens_generated", 0)
        }

    return jsonify({
        "success": True,
        "hardware": ollama_client.get_hardware_status(),
        "benchmark": results
    })



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


@app.route('/api/ai/status', methods=['GET'])
def ai_status():
    """Returns AI Assistant configuration status and model info."""
    return jsonify(ai_assistant.get_status())


@app.route('/api/ai/analyze', methods=['POST'])
def ai_analyze():
    """
    Analyzes VITAL source code in real time and returns advisory suggestions.
    Guaranteed: Strictly read-only; never modifies user source code.
    Expects JSON: { "code": str, "language": Optional[str], "diagnostics": Optional[dict], "source_version": Optional[int] }
    """
    if not request.is_json:
        return jsonify({
            "success": False,
            "error": "Invalid request format. Expected JSON body.",
            "analysis_summary": "Request error: Payload must be JSON.",
            "findings": []
        }), 400

    data = request.get_json() or {}
    code = data.get('code', '')
    language = data.get('language', 'English')
    diagnostics = data.get('diagnostics')
    source_version = data.get('source_version', 1)

    result = ai_assistant.analyze(
        source_code=code,
        diagnostics=diagnostics,
        language=language,
        source_version=source_version
    )
    return jsonify(result)


@app.route('/api/ai/explain-error', methods=['POST'])
def ai_explain_error():
    """
    Provides clear pedagogical explanation for compiler errors or runtime exceptions.
    Guaranteed: Strictly read-only; never modifies user source code.
    Expects JSON: { "code": str, "error_details": dict, "diagnostics": Optional[dict], "language": Optional[str] }
    """
    if not request.is_json:
        return jsonify({
            "success": False,
            "error": "Invalid request format. Expected JSON body."
        }), 400

    data = request.get_json() or {}
    code = data.get('code', '')
    error_details = data.get('error_details') or {}
    diagnostics = data.get('diagnostics')
    language = data.get('language', 'English')

    result = ai_assistant.explain_error(
        source_code=code,
        error_details=error_details,
        diagnostics=diagnostics,
        language=language
    )
    return jsonify(result)


# ============================================================================
# SECURITY & LOCAL OLLAMA AGENT ENDPOINTS
# ============================================================================

@app.route('/api/security/status', methods=['GET'])
def security_status():
    """Returns local Ollama service availability and configuration."""
    is_online, msg, details = ollama_client.check_health(force_refresh=True)
    return jsonify({
        "success": True,
        "ollama_online": is_online,
        "ollama_healthy": is_online,
        "model": ollama_client.model_name,
        "message": msg,
        "details": details,
        "config": ollama_client.get_config(),
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
    Executes multi-stage static security scan and optional Ollama AI investigation.
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
    Employs the shared stage-aware AIRemediationEngine powered by local Ollama (qwen2.5-coder:7b-instruct).
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
    Asynchronously refines an existing deterministic proposal using Ollama AI.
    If Ollama is offline or times out, safely retains the deterministic proposal.
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    code = data.get('code') or data.get('source_code', '')
    finding_id = data.get('finding_id', '')
    finding_data = data.get('finding', {})
    current_fix = data.get('current_fix', {})
    language = data.get('language', 'English')

    refined = security_coordinator.refine_fix_with_ollama(
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
    run_id = data.get('run_id')
    source_revision = int(data.get('source_revision', 1))
    resume_from = data.get('resume_from')

    tracker = PipelineRunTracker(run_id=run_id, source_revision=source_revision)
    execute_pipeline_with_tracker(
        source_code=code,
        language_hint=language,
        run_ai_security=use_ai_security,
        tracker=tracker,
        pause_on_error=pause_on_error,
        resume_from=resume_from,
        source_revision=source_revision
    )

    return jsonify(tracker.to_dict())


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
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    data = request.get_json() or {}
    code = data.get('code') or data.get('source_code', '')
    language = data.get('language', '')
    use_ai_security = data.get('use_ai_security', True)
    pause_on_error = data.get('pause_on_error', False)
    run_id = data.get('run_id')
    source_revision = int(data.get('source_revision', 1))
    resume_from = data.get('resume_from')

    tracker = PipelineRunTracker(run_id=run_id, source_revision=source_revision)

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
                "resume_from": resume_from,
                "source_revision": source_revision
            },
            daemon=True
        )
        worker_thread.start()

        # Yield events from queue until finished
        while True:
            try:
                event = tracker.event_queue.get(timeout=0.1)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("event") in ("pipeline_finish", "pipeline_paused"):
                    break
            except queue.Empty:
                if tracker.is_finished and tracker.event_queue.empty():
                    break
                continue

    return Response(
        generate_events(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )


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
    run_id = data.get('run_id')

    if not code or not code.strip():
        return jsonify({"success": False, "error": "Source code is empty"}), 400

    # Execute full pipeline with auto_generate_report to assemble genuine artifacts
    tracker = PipelineRunTracker(run_id=run_id)
    execute_pipeline_with_tracker(
        source_code=code,
        language_hint=language,
        run_ai_security=False,
        tracker=tracker,
        pause_on_error=False
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

    tracker.complete_final_report()
    result = tracker.to_dict()
    return jsonify({
        "success": True,
        "run_id": result.get("run_id"),
        "status": result.get("status"),
        "artifacts": result.get("artifacts"),
        "elapsed_ms": result.get("elapsed_ms"),
        "stages": result.get("stages"),
        "is_incomplete": bool(failed_mandatory)
    })


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
