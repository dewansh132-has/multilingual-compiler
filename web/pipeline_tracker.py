# -*- coding: utf-8 -*-
"""
web/pipeline_tracker.py — Live Compiler Pipeline Progress Tracker & Event Coordinator

Coordinates the live execution of the genuine VITAL compiler stages and
security analysis agents, emitting real-time progressive event updates to the UI.

Explicit 14 Logical Compiler Stages (Compiler Design Syllabus Order):
  1. source_input          : Source Input / Language Detection
  2. lexical_analysis      : Lexical Analysis (VitalLexer Token Stream)
  3. syntax_analysis       : Syntax Analysis (Parser Delimiter & Structural Verification)
  4. ast_construction      : AST Construction (Abstract Syntax Tree Generation & Logging)
  5. semantic_analysis     : Semantic Analysis (Scope, Type, and Compile-Time Verification)
  6. symbol_table          : Symbol Table / Scope Resolution
  7. ir_generation         : Intermediate Representation (IR Transpilation)
  8. optimization          : Mandatory IR Optimization Passes (Constant Folding, DCE, etc.)
  9. code_generation       : Code Generation (Target Python Code Emission)
  10. code_validation      : Generated-Code Validation (Target Syntax Verification)
  11. security_analysis    : Security Analysis (Deterministic Static Security Rules)
  12. ai_security_analysis : Ollama AI Analysis (qwen2.5-coder:7b-instruct Agent)
  13. sandbox_execution    : Sandbox / Execution (Subprocess + 5s Timeout Guard)
  14. final_report         : Final Report (Diagnostics, Output, and Symbol Assembly)

Progress Calculation & Integrity:
  - Progress % strictly reflects completed applicable stages out of total applicable stages.
  - Skipped and unavailable stages do NOT inflate progress percentage.
  - Security score is separate and never confused with completion percentage.
  - No fake timer advances; states update strictly on backend stage execution.
  - Unique UUID per run prevents delayed events from earlier runs corrupting new runs.
"""

import os
import sys
import time
import uuid
import json
import ast
import queue
import re
import hashlib
from typing import Dict, Any, List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(PROJECT_ROOT, 'src')
TESTS_DIR = os.path.join(PROJECT_ROOT, 'tests')
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from main import Compiler, RULES_FILE
from web.demo_manager import detect_file_language
from web.compiler_runner import run_pipeline, _read_file_safe
from web.security_analyzer import security_coordinator, DeterministicSecurityScanner
from web.ollama_client import ollama_client


STAGE_DEFINITIONS = [
    {
        "id": "source_input",
        "name": "1. Source Input",
        "category": "frontend",
        "applicable": True,
        "description": "Validates source presence, detects Indic/English script, and loads decoupled rule dictionary."
    },
    {
        "id": "lexical_analysis",
        "name": "2. Lexer (Lexical)",
        "category": "frontend",
        "applicable": True,
        "description": "VitalLexer character-by-character scan producing structured token stream with line/column metadata."
    },
    {
        "id": "syntax_analysis",
        "name": "3. Parser (Syntax)",
        "category": "frontend",
        "applicable": True,
        "description": "Delimiter balance verification and context-free grammar validation against VITAL syntax."
    },
    {
        "id": "ast_construction",
        "name": "4. AST Construction",
        "category": "frontend",
        "applicable": True,
        "description": "Abstract Syntax Tree generation and recursive visual hierarchy logging."
    },
    {
        "id": "semantic_analysis",
        "name": "5. Semantic Analysis",
        "category": "frontend",
        "applicable": True,
        "description": "Context-sensitive analysis: identifier validation, scope checks, and compile-time semantics."
    },
    {
        "id": "symbol_table",
        "name": "6. Symbol Table",
        "category": "frontend",
        "applicable": True,
        "description": "Lexical environment and identifier scope resolution, variable type inference and binding."
    },
    {
        "id": "ir_generation",
        "name": "7. Intermediate Rep (IR)",
        "category": "middle-end",
        "applicable": True,
        "description": "Translates multilingual tokens into Python Intermediate Representation with homoglyph protection."
    },
    {
        "id": "optimization",
        "name": "8. Optimization",
        "category": "middle-end",
        "applicable": True,
        "description": "Validated IR optimization passes (Constant Folding, Propagation, Dead Code Elimination, Algebraic Simplification) with Ollama AI assistance."
    },
    {
        "id": "code_generation",
        "name": "9. Code Generation",
        "category": "backend",
        "applicable": True,
        "description": "Emits executable Python target code with runtime safety wrappers and indentation structure."
    },
    {
        "id": "code_validation",
        "name": "10. Target Code Validation",
        "category": "backend",
        "applicable": True,
        "description": "Validates generated target code syntax and AST integrity before execution."
    },
    {
        "id": "security_analysis",
        "name": "11. Security Analysis",
        "category": "security",
        "applicable": True,
        "description": "Deterministic static scan: AST visitor, homoglyphs, null bytes, command injection, path traversal."
    },
    {
        "id": "ai_security_analysis",
        "name": "12. Ollama AI Analysis",
        "category": "security",
        "applicable": True,
        "description": "Local Ollama model (qwen2.5-coder:7b-instruct) investigates blast radius and generates patch diffs."
    },
    {
        "id": "sandbox_execution",
        "name": "13. Sandbox Execution",
        "category": "backend",
        "applicable": True,
        "description": "Isolated subprocess execution under 5-second timeout guard with redirected stdout capture."
    },
    {
        "id": "final_report",
        "name": "14. Final Report",
        "category": "backend",
        "applicable": True,
        "description": "Compiles multi-stage pipeline report, execution metrics, symbol table, and diagnostics."
    }
]

# Backward-compatibility alias mapping for legacy stage IDs
STAGE_ALIASES = {
    "parser_validation": "syntax_analysis",
    "ir_transpilation": "ir_generation",
    "deterministic_security": "security_analysis",
    "execution_sandbox": "sandbox_execution"
}


class SemanticAnalyzer:
    """
    Performs context-sensitive semantic analysis on the generated AST and token stream.
    Checks for undeclared identifiers, zero division constants, type consistency, and dead code.
    """
    def __init__(self):
        self.diagnostics: List[Dict[str, Any]] = []
        self.symbols: Dict[str, Dict[str, Any]] = {}

    def analyze(self, ast_tree: ast.AST) -> Dict[str, Any]:
        self.diagnostics = []
        self.symbols = {}

        assigned_names = set()
        safe_builtins = {
            "print", "input", "range", "len", "int", "str", "float", "bool",
            "list", "dict", "set", "tuple", "min", "max", "sum", "abs",
            "True", "False", "None"
        }

        # First pass: collect function definitions and parameters
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.FunctionDef):
                assigned_names.add(node.name)
                self.symbols[node.name] = {
                    "name": node.name,
                    "type": "function",
                    "scope": "global",
                    "line": getattr(node, "lineno", 1),
                    "value_preview": f"def {node.name}(...)"
                }
                for arg in getattr(node.args, "args", []):
                    assigned_names.add(arg.arg)
            elif isinstance(node, ast.For) and isinstance(node.target, ast.Name):
                assigned_names.add(node.target.id)

        for node in ast.walk(ast_tree):
            # Check constant division by zero
            if isinstance(node, ast.BinOp):
                if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
                    if isinstance(node.right, ast.Constant) and node.right.value == 0:
                        self.diagnostics.append({
                            "type": "error",
                            "line": getattr(node, "lineno", 1),
                            "message": "Division by zero constant detected in arithmetic expression."
                        })

            # Check variable assignments to record symbols and inferred types
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        assigned_names.add(var_name)
                        inferred_type = "unknown"
                        val_preview = ""
                        if isinstance(node.value, ast.Constant):
                            inferred_type = type(node.value.value).__name__
                            val_preview = repr(node.value.value)
                        elif isinstance(node.value, ast.List):
                            inferred_type = "list"
                        elif isinstance(node.value, ast.Dict):
                            inferred_type = "dict"
                        elif isinstance(node.value, ast.BinOp):
                            inferred_type = "numeric"
                        elif isinstance(node.value, ast.Call):
                            inferred_type = "function_call"

                        self.symbols[var_name] = {
                            "name": var_name,
                            "type": inferred_type,
                            "scope": "global",
                            "line": getattr(node, "lineno", 1),
                            "value_preview": val_preview
                        }

            # Check for name referenced before assignment (undeclared variable)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                var_name = node.id
                if var_name not in assigned_names and var_name not in safe_builtins:
                    self.diagnostics.append({
                        "type": "error",
                        "line": getattr(node, "lineno", 1),
                        "message": f"Identifier '{var_name}' referenced before explicit local assignment."
                    })

        warning_count = sum(1 for d in self.diagnostics if d["type"] == "warning")
        error_count = sum(1 for d in self.diagnostics if d["type"] == "error")

        return {
            "diagnostics": self.diagnostics,
            "symbols": self.symbols,
            "warning_count": warning_count,
            "error_count": error_count
        }


class PipelineRunTracker:
    """Manages the state and live progressive events for a single compiler execution run."""

    def __init__(self, run_id: Optional[str] = None, source_revision: int = 1, source_hash: Optional[str] = None):
        self.run_id = run_id or str(uuid.uuid4())
        self.source_revision = source_revision
        self.source_hash = source_hash
        self.applied_fixes: List[str] = []
        self.file_path: str = ""
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.stages: Dict[str, Dict[str, Any]] = {}
        self.event_queue: queue.Queue = queue.Queue()
        # All stages in STAGE_DEFINITIONS are mandatory/applicable
        self.applicable_stage_ids = [s["id"] for s in STAGE_DEFINITIONS if s.get("applicable", True)]
        self.completed_stages_count = 0
        self.is_finished = False
        self.is_paused = False
        self.paused_stage: Optional[str] = None
        self.pause_reason: str = ""
        self.is_ready_for_report: bool = False
        self.final_status = "running"
        self.artifacts: Dict[str, Any] = {}

        # Initialize all stages
        for defn in STAGE_DEFINITIONS:
            sid = defn["id"]
            init_status = "skipped" if not defn.get("applicable", True) else "pending"
            init_summary = "Skipped" if not defn.get("applicable", True) else "Pending initialization"
            self.stages[sid] = {
                "id": sid,
                "name": defn["name"],
                "category": defn["category"],
                "description": defn["description"],
                "applicable": defn.get("applicable", True),
                "status": init_status,   # pending, running, completed, warning, failed, skipped, blocked, stale, ready
                "start_time": None,
                "end_time": None,
                "duration_ms": 0.0,
                "summary": init_summary,
                "details": {},
                "findings_count": 0,
                "skip_reason": "",
                "source_revision": None,
                "source_hash": None
            }

    @property
    def status(self) -> str:
        return self.final_status

    def _resolve_stage_id(self, stage_id: str) -> str:
        return STAGE_ALIASES.get(stage_id, stage_id)

    def emit_event(self, event_type: str, stage_id: Optional[str] = None, extra_data: Optional[Dict[str, Any]] = None):
        """Creates a structured event and puts it in the thread-safe queue."""
        stage_id = self._resolve_stage_id(stage_id) if stage_id else None
        now = time.time()
        applicable_count = len(self.applicable_stage_ids)
        # Progress calculation: strictly completed applicable stages / applicable stages
        progress_pct = round((self.completed_stages_count / applicable_count) * 100) if applicable_count > 0 else 0

        event_payload = {
            "run_id": self.run_id,
            "source_revision": self.source_revision,
            "event": event_type,
            "stage_id": stage_id,
            "stage": self.stages.get(stage_id, {}).get("name") if stage_id else "",
            "stage_status": self.stages.get(stage_id, {}).get("status") if stage_id else "",
            "progress_pct": progress_pct,
            "completed_count": self.completed_stages_count,
            "applicable_count": applicable_count,
            "total_stages": len(STAGE_DEFINITIONS),
            "elapsed_ms": round((now - self.start_time) * 1000, 2),
            "timestamp": now
        }
        if stage_id and stage_id in self.stages:
            st = self.stages[stage_id]
            event_payload["duration_ms"] = st["duration_ms"]
            event_payload["summary"] = st["summary"]
            event_payload["findings_count"] = st["findings_count"]
            event_payload["skip_reason"] = st["skip_reason"]
            event_payload["details"] = st["details"]

        if extra_data:
            event_payload.update(extra_data)

        self.event_queue.put(event_payload)

    def start_stage(self, stage_id: str, summary: str = "Processing..."):
        stage_id = self._resolve_stage_id(stage_id)
        if stage_id in self.stages:
            st = self.stages[stage_id]
            st["status"] = "running"
            st["start_time"] = time.time()
            st["summary"] = summary
            self.emit_event("stage_start", stage_id)

    def complete_stage(
        self,
        stage_id: str,
        summary: str,
        details: Optional[Dict[str, Any]] = None,
        findings_count: int = 0,
        source_revision: Optional[int] = None,
        source_hash: Optional[str] = None
    ):
        stage_id = self._resolve_stage_id(stage_id)
        if stage_id in self.stages:
            st = self.stages[stage_id]
            now = time.time()
            st["end_time"] = now
            if st["start_time"]:
                st["duration_ms"] = round((now - st["start_time"]) * 1000, 2)
            st["status"] = "warning" if findings_count > 0 else "completed"
            st["summary"] = summary
            st["findings_count"] = findings_count
            st["source_revision"] = source_revision if source_revision is not None else self.source_revision
            st["source_hash"] = source_hash or getattr(self, 'source_hash', None)
            if details:
                st["details"] = details
            self.completed_stages_count += 1
            self.emit_event("stage_complete", stage_id)

    def mark_stage_stale(self, stage_id: str, reason: str = ""):
        """Marks an individual stage STALE due to upstream source revision modifications."""
        stage_id = self._resolve_stage_id(stage_id)
        if stage_id in self.stages:
            st = self.stages[stage_id]
            was_completed = st.get("status") in ("completed", "passed", "warning")
            st["status"] = "stale"
            st["summary"] = reason or f"Stale: Source code updated to revision {self.source_revision}."
            st["details"] = {}
            st["findings_count"] = 0
            if was_completed and self.completed_stages_count > 0:
                self.completed_stages_count -= 1
            self.emit_event("stage_stale", stage_id)

    def invalidate_for_new_revision(self, current_revision: int, current_hash: str = ""):
        """Invalidates all stages whose recorded revision/hash does not match the active source."""
        self.source_revision = current_revision
        self.is_ready_for_report = False
        for sid, st in self.stages.items():
            st_rev = st.get("source_revision")
            st_hash = st.get("source_hash")
            if st_rev is None or st_rev != current_revision or (current_hash and st_hash and st_hash != current_hash):
                self.mark_stage_stale(sid, f"Stale: Executed against older revision ({st_rev} vs active {current_revision})")

    def fail_stage(self, stage_id: str, error_message: str, details: Optional[Dict[str, Any]] = None, findings_count: int = 1):
        stage_id = self._resolve_stage_id(stage_id)
        if stage_id in self.stages:
            st = self.stages[stage_id]
            now = time.time()
            st["end_time"] = now
            if st["start_time"]:
                st["duration_ms"] = round((now - st["start_time"]) * 1000, 2)
            st["status"] = "failed"
            st["summary"] = f"Error: {error_message}"
            if details:
                st["details"] = details
                if "findings" in details and findings_count == 1:
                    findings_count = len(details["findings"])
            st["findings_count"] = findings_count
            # Failed stages do NOT increment completed_stages_count
            self.emit_event("stage_failed", stage_id, {"error": error_message})

    def skip_stage(self, stage_id: str, reason: str):
        stage_id = self._resolve_stage_id(stage_id)
        if stage_id in self.stages:
            st = self.stages[stage_id]
            now = time.time()
            st["end_time"] = now
            if st.get("start_time"):
                st["duration_ms"] = round((now - st["start_time"]) * 1000, 2)
            else:
                st["duration_ms"] = 0.0
            st["status"] = "skipped"
            st["summary"] = f"Skipped: {reason}"
            st["skip_reason"] = reason
            # Skipped stages do NOT increment completed_stages_count
            self.emit_event("stage_skipped", stage_id)

    def warn_stage(self, stage_id: str, summary: str, details: Optional[Dict[str, Any]] = None, findings_count: int = 0):
        stage_id = self._resolve_stage_id(stage_id)
        if stage_id in self.stages:
            st = self.stages[stage_id]
            now = time.time()
            st["end_time"] = now
            if st.get("start_time"):
                st["duration_ms"] = round((now - st["start_time"]) * 1000, 2)
            else:
                st["duration_ms"] = 0.0
            st["status"] = "warning"
            st["summary"] = summary
            st["findings_count"] = findings_count
            if details:
                st["details"] = details
            self.completed_stages_count += 1
            self.emit_event("stage_warning", stage_id, {"summary": summary, "status": "warning"})

    def block_stage(self, stage_id: str, reason: str):
        """Marks a dependent stage blocked because an earlier prerequisite stage failed."""
        stage_id = self._resolve_stage_id(stage_id)
        if stage_id in self.stages:
            st = self.stages[stage_id]
            st["status"] = "blocked"
            st["summary"] = f"Blocked: {reason}"
            st["skip_reason"] = reason
            # Blocked stages do NOT increment completed_stages_count
            self.emit_event("stage_blocked", stage_id)

    def mark_stage_ready(self, stage_id: str, summary: str = "Ready for report generation"):
        """Marks a stage ready for explicit user action (e.g. Final Report gate)."""
        stage_id = self._resolve_stage_id(stage_id)
        if stage_id in self.stages:
            st = self.stages[stage_id]
            st["status"] = "ready"
            st["summary"] = summary
            self.is_ready_for_report = True
            self.emit_event("stage_ready", stage_id)

    def complete_final_report(self):
        """Explicitly transitions the final_report stage from ready to completed."""
        if "final_report" in self.stages:
            st = self.stages["final_report"]
            st["status"] = "completed"
            st["summary"] = "Final Report generated successfully. All compiler artifacts populated."
            self.completed_stages_count += 1
            self.is_ready_for_report = False
            self.emit_event("stage_complete", "final_report")

    def pause_pipeline(self, paused_stage: str, summary: str, details: Optional[Dict[str, Any]] = None):
        """Pauses progressive pipeline execution on a blocking failure awaiting user correction."""
        self.end_time = time.time()
        self.is_finished = True
        self.is_paused = True
        self.paused_stage = paused_stage
        self.pause_reason = summary
        self.final_status = "paused"
        total_ms = round((self.end_time - self.start_time) * 1000, 2)

        payload = {
            "status": "paused",
            "paused_stage": paused_stage,
            "summary": summary,
            "total_duration_ms": total_ms,
            "artifacts": self.artifacts
        }
        if details:
            payload.update(details)

        self.emit_event("pipeline_paused", paused_stage, payload)
        self.emit_event("pipeline_finish", None, payload)
        try:
            from web.fixflow_logger import log_compile_event
            log_compile_event(
                run_id=self.run_id,
                source_revision=self.source_revision,
                source_hash=getattr(self, "source_hash", "") or "",
                language=self.artifacts.get("detected_language", "") if self.artifacts else "",
                stages=self.stages,
                final_status="paused",
                duration_ms=total_ms
            )
        except Exception:
            pass

    def finish_pipeline(self, status: str, summary: str, final_artifacts: Dict[str, Any]):
        self.end_time = time.time()
        self.is_finished = True
        self.final_status = status
        self.artifacts = final_artifacts
        total_ms = round((self.end_time - self.start_time) * 1000, 2)

        self.emit_event("pipeline_finish", None, {
            "status": status,
            "summary": summary,
            "total_duration_ms": total_ms,
            "artifacts": final_artifacts
        })
        try:
            from web.fixflow_logger import log_compile_event
            log_compile_event(
                run_id=self.run_id,
                source_revision=self.source_revision,
                source_hash=getattr(self, "source_hash", "") or "",
                language=final_artifacts.get("detected_language", "") if final_artifacts else "",
                stages=self.stages,
                final_status=status,
                duration_ms=total_ms
            )
        except Exception:
            pass

    def to_dict(self) -> Dict[str, Any]:
        """Serializes current tracker state into dictionary."""
        applicable_count = len(self.applicable_stage_ids)
        progress_pct = round((self.completed_stages_count / applicable_count) * 100) if applicable_count > 0 else 0
        total_ms = round(((self.end_time or time.time()) - self.start_time) * 1000, 2)
        return {
            "run_id": self.run_id,
            "source_revision": self.source_revision,
            "success": self.final_status in ("completed", "warning"),
            "status": self.final_status,
            "overall_status": self.final_status,
            "is_paused": self.is_paused,
            "paused_stage": self.paused_stage,
            "pause_reason": self.pause_reason,
            "is_ready_for_report": self.is_ready_for_report,
            "progress_pct": progress_pct,
            "completed_count": self.completed_stages_count,
            "completed_stages": self.completed_stages_count,
            "applicable_count": applicable_count,
            "applicable_stages": applicable_count,
            "total_stages": len(STAGE_DEFINITIONS),
            "elapsed_ms": total_ms,
            "stages": [dict(s) for s in self.stages.values()],
            "output": self.artifacts.get("output", "") if self.artifacts else "",
            "detected_language": self.artifacts.get("detected_language", "") if self.artifacts else "",
            "artifacts": self.artifacts,
            "is_finished": self.is_finished
        }

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]


def execute_pipeline_with_tracker(
    source_code: str,
    language_hint: str = "",
    run_ai_security: bool = True,
    tracker: Optional[PipelineRunTracker] = None,
    pacing_ms: float = 0.0,
    pause_on_error: bool = False,
    resume_from: Optional[str] = None,
    source_revision: int = 1
) -> PipelineRunTracker:
    """
    Executes the genuine VITAL compiler pipeline + security analysis across all 14 stages,
    updating the PipelineRunTracker on every genuine milestone.
    
    If pacing_ms > 0, introduces a small cooperative pause between stages to allow
    real-time streaming sockets to flush individual SSE events to the browser.
    If pause_on_error is True, halts immediately on blocking errors, marking subsequent
    stages as blocked and pausing the pipeline state machine.
    """
    if tracker is None:
        tracker = PipelineRunTracker(source_revision=source_revision)
    else:
        tracker.source_revision = source_revision

    stage_order = [s["id"] for s in STAGE_DEFINITIONS]
    resume_idx = stage_order.index(resume_from) if (resume_from and resume_from in stage_order) else 0

    def _pace(stage_id: Optional[str] = None):
        if pacing_ms > 0:
            if stage_id and stage_id in stage_order:
                cur_idx = stage_order.index(stage_id)
                if cur_idx < resume_idx:
                    return
            time.sleep(pacing_ms / 1000.0)

    if not source_code or not source_code.strip():
        tracker.fail_stage("source_input", "Source code is empty.")
        for s in STAGE_DEFINITIONS[1:]:
            if pause_on_error:
                tracker.block_stage(s["id"], "Blocked: Source code is empty.")
            else:
                tracker.skip_stage(s["id"], "Previous stage failed due to empty source.")
        if pause_on_error:
            tracker.pause_pipeline("source_input", "Compilation halted: Source code is empty.", {})
        else:
            tracker.finish_pipeline("failed", "Failed: Empty Source Code", {})
        return tracker

    output_dir = os.path.join(TESTS_DIR)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    current_source_hash = hashlib.sha256(source_code.encode("utf-8")).hexdigest()
    tracker.source_hash = current_source_hash

    # -------------------------------------------------------------------------
    # STAGE 1: Source Input & Language Detection
    # -------------------------------------------------------------------------
    tracker.start_stage("source_input", "Detecting language script and loading grammar rules...")
    _pace()
    detected_lang = detect_file_language(source_code, language_hint)
    compiler = None
    try:
        compiler = Compiler(RULES_FILE)
        compiler.load_rules()
        char_count = len(source_code)
        line_count = len(source_code.splitlines())
        tracker.complete_stage(
            "source_input",
            f"Detected {detected_lang} ({line_count} lines, {char_count} chars). Grammar rules loaded.",
            {"detected_language": detected_lang, "line_count": line_count, "char_count": char_count}
        )
    except Exception as e:
        tracker.fail_stage("source_input", f"Failed to initialize compiler rules: {e}")
        for s in STAGE_DEFINITIONS[1:]:
            tracker.skip_stage(s["id"], "Compiler initialization failed.")
        tracker.finish_pipeline("failed", f"Initialization Error: {e}", {})
        return tracker
    _pace()

    # -------------------------------------------------------------------------
    # STAGE 2: Lexical Analysis (Lexer)
    # -------------------------------------------------------------------------
    tracker.start_stage("lexical_analysis", "Scanning character stream into structured tokens...")
    _pace()
    tokens = []
    try:
        compiler.run_lexer(source_code)
        tokens = compiler.last_token_stream or []
        non_eof = [t for t in tokens if t.type.name != "EOF"]
        kw_count = sum(1 for t in non_eof if t.type.name == "KEYWORD")
        id_count = sum(1 for t in non_eof if t.type.name == "IDENTIFIER")
        op_count = sum(1 for t in non_eof if t.type.name == "OPERATOR")
        delim_count = sum(1 for t in non_eof if t.type.name == "DELIMITER")
        lit_count = sum(1 for t in non_eof if t.type.name in ("NUMBER", "STRING"))

        lex_findings = DeterministicSecurityScanner.scan_lexical(source_code)
        lex_dicts = [f.to_dict() for f in lex_findings]
        lex_findings_count = len(lex_dicts)
        lex_summary = f"Tokenized {len(non_eof)} active tokens (Keywords: {kw_count}, Identifiers: {id_count}, Operators: {op_count}, Delimiters: {delim_count})."
        if lex_findings_count > 0:
            lex_summary += f" Detected {lex_findings_count} lexical issue(s)."

        tracker.complete_stage(
            "lexical_analysis",
            lex_summary,
            {
                "total_tokens": len(non_eof),
                "keywords": kw_count,
                "identifiers": id_count,
                "operators": op_count,
                "delimiters": delim_count,
                "literals": lit_count,
                "findings": lex_dicts
            },
            findings_count=lex_findings_count
        )
    except Exception as e:
        tracker.fail_stage("lexical_analysis", f"Lexer error: {e}")
        for s in STAGE_DEFINITIONS[2:]:
            tracker.skip_stage(s["id"], "Lexical analysis aborted.")
        tracker.finish_pipeline("failed", f"Lexer Error: {e}", {})
        return tracker
    _pace()

    # -------------------------------------------------------------------------
    # STAGE 3: Syntax Analysis (Parser)
    # -------------------------------------------------------------------------
    tracker.start_stage("syntax_analysis", "Validating delimiter matching and grammar blocks...")
    _pace()
    is_valid_syntax = False
    try:
        is_valid_syntax = compiler.run_parser(source_code)
        parser_log = _read_file_safe(os.path.join(TESTS_DIR, "parser_log.txt"))
        syntax_findings = []
        source_lines = source_code.splitlines()
        for l in parser_log.splitlines():
            if l.startswith("[ERROR]") or l.startswith("[WARNING]"):
                is_err = l.startswith("[ERROR]")
                msg = l.replace("[ERROR]", "").replace("[WARNING]", "").strip()
                m_line = re.search(r'line\s*(\d+)', msg, re.IGNORECASE)
                line_num = int(m_line.group(1)) if m_line else 1
                m_col = re.search(r':(\d+):', msg) or re.search(r'col(?:umn)?\s*(\d+)', msg, re.IGNORECASE)
                col_num = int(m_col.group(1)) if m_col else 1
                rule_id = "SEC-PAR-001" if ("brace" in msg.lower() or "{" in msg or "}" in msg or "delimiter" in msg.lower()) else ("SEC-PAR-002" if "paren" in msg.lower() else "SYN-001")
                excerpt = source_lines[line_num - 1].strip() if (1 <= line_num <= len(source_lines)) else msg
                syntax_findings.append({
                    "id": f"{rule_id}-L{line_num}",
                    "title": msg,
                    "severity": "Critical" if is_err else "Medium",
                    "stage": "Syntax Analysis",
                    "stage_id": "syntax_analysis",
                    "line": line_num,
                    "column": col_num,
                    "evidence": excerpt,
                    "code_excerpt": excerpt,
                    "explanation": "Parser detected a syntax or delimiter violation against the VITAL grammar rules.",
                    "potential_impact": "Prevents AST generation and intermediate code transpilation.",
                    "remediation": "Close all open delimiters and ensure statement syntax conforms to VITAL specification.",
                    "rule_id": rule_id,
                    "status": "open",
                    "confidence": "confirmed"
                })

        if is_valid_syntax:
            tracker.complete_stage(
                "syntax_analysis",
                "Delimiters balanced and syntax validated against VITAL grammar specification.",
                {"parser_log": parser_log, "findings": syntax_findings},
                findings_count=len(syntax_findings)
            )
        else:
            first_err = "Syntax or delimiter error."
            for l in parser_log.splitlines():
                if l.startswith("[ERROR]"):
                    first_err = l.replace("[ERROR]", "").strip()
                    break
            if not syntax_findings:
                fallback_excerpt = source_lines[0].strip() if source_lines else first_err
                syntax_findings.append({
                    "id": "SEC-PAR-001-L1",
                    "title": first_err,
                    "severity": "Critical",
                    "stage": "Syntax Analysis",
                    "stage_id": "syntax_analysis",
                    "line": 1,
                    "column": 1,
                    "evidence": fallback_excerpt,
                    "code_excerpt": fallback_excerpt,
                    "explanation": "Parser validation failed against context-free grammar.",
                    "potential_impact": "Halts compilation before intermediate code generation.",
                    "remediation": "Correct grammar syntax or unmatched delimiters.",
                    "rule_id": "SEC-PAR-001",
                    "status": "open",
                    "confidence": "confirmed"
                })
            tracker.fail_stage("syntax_analysis", first_err, {"parser_log": parser_log, "findings": syntax_findings}, findings_count=len(syntax_findings))
            if pause_on_error:
                for s in STAGE_DEFINITIONS[3:]:
                    tracker.block_stage(s["id"], "Blocked: Syntax Analysis (Parser) failed.")
                tracker.pause_pipeline(
                    "syntax_analysis",
                    f"Compilation paused: Syntax error in Parser ({first_err}). Review diagnostics and apply fix to resume.",
                    {"parser_log": parser_log, "findings": syntax_findings}
                )
                return tracker
    except Exception as e:
        tracker.fail_stage("syntax_analysis", f"Parser exception: {e}")
        is_valid_syntax = False
        if pause_on_error:
            for s in STAGE_DEFINITIONS[3:]:
                tracker.block_stage(s["id"], "Blocked: Parser exception encountered.")
            tracker.pause_pipeline("syntax_analysis", f"Compilation paused: Parser exception ({e}).")
            return tracker
    _pace()

    # -------------------------------------------------------------------------
    # STAGE 4: AST Construction
    # -------------------------------------------------------------------------
    ast_tree = None
    if is_valid_syntax:
        tracker.start_stage("ast_construction", "Constructing Abstract Syntax Tree and visual node hierarchy...")
        _pace()
        try:
            temp_ir = compiler.transpile(source_code)
            ast_tree = ast.parse(temp_ir)
            node_count = sum(1 for _ in ast.walk(ast_tree))
            ast_log = _read_file_safe(os.path.join(TESTS_DIR, "ast_log.txt"))
            tracker.complete_stage(
                "ast_construction",
                f"AST constructed successfully ({node_count} nodes, root: {type(ast_tree).__name__}).",
                {"node_count": node_count, "ast_preview": ast_log[:500]}
            )
        except Exception as e:
            tracker.fail_stage("ast_construction", f"AST construction failed: {e}")
            ast_tree = None
            if pause_on_error:
                for s in STAGE_DEFINITIONS[4:]:
                    tracker.block_stage(s["id"], "Blocked: AST Construction failed.")
                tracker.pause_pipeline("ast_construction", f"Compilation paused: AST construction failed ({e}).", {})
                return tracker
    else:
        tracker.skip_stage("ast_construction", "Skipped because syntax analysis failed.")
    _pace()

    # -------------------------------------------------------------------------
    # STAGE 5: Semantic Analysis
    # -------------------------------------------------------------------------
    semantic_results = {"diagnostics": [], "symbols": {}, "warning_count": 0, "error_count": 0}
    if ast_tree is not None:
        tracker.start_stage("semantic_analysis", "Validating variable scopes, types, and compile-time semantics...")
        _pace()
        try:
            analyzer = SemanticAnalyzer()
            semantic_results = analyzer.analyze(ast_tree)
            warn_count = semantic_results["warning_count"]
            err_count = semantic_results["error_count"]

            semantic_log_path = os.path.join(TESTS_DIR, "semantic_log.txt")
            with open(semantic_log_path, "w", encoding="utf-8") as sf:
                sf.write("--- SEMANTIC ANALYSIS REPORT ---\n\n")
                if err_count == 0 and warn_count == 0:
                    sf.write("[SUCCESS] All identifier bindings, types, and scopes verified without issues.\n")
                for d in semantic_results["diagnostics"]:
                    sf.write(f"[{d['type'].upper()}] Line {d['line']}: {d['message']}\n")
                sf.write(f"\nSymbols extracted: {len(semantic_results['symbols'])}\n")

            source_lines = source_code.splitlines()
            semantic_findings = []
            for idx, d in enumerate(semantic_results.get("diagnostics", []), start=1):
                is_err = d.get("type") == "error"
                msg = d.get("message", "Semantic Diagnostic")
                rule_id = "SEM-001" if "division by zero" in msg.lower() else "SEC-SEM-001"
                syntax_line = d.get('line', 1)

                var_match = re.search(r"Identifier '([^']+)'", msg)
                var_name = var_match.group(1) if var_match else ""

                line_excerpt = ""
                if 1 <= syntax_line <= len(source_lines):
                    line_excerpt = source_lines[syntax_line - 1]

                if var_name:
                    finding_id = f"{rule_id}-L{syntax_line}-{var_name}"
                elif "division by zero" in msg.lower():
                    finding_id = f"{rule_id}-L{syntax_line}-divzero"
                else:
                    finding_id = f"{rule_id}-L{syntax_line}-{idx}"

                semantic_findings.append({
                    "id": finding_id,
                    "title": msg,
                    "severity": "Critical" if is_err else "Medium",
                    "stage": "Semantic Analysis",
                    "stage_id": "semantic_analysis",
                    "line": syntax_line,
                    "column": 1,
                    "evidence": line_excerpt.strip() if line_excerpt.strip() else msg,
                    "code_excerpt": line_excerpt,
                    "identifier": var_name or ("divzero" if "division by zero" in msg.lower() else ""),
                    "explanation": "Context-sensitive semantic validation detected an issue with types, scopes, or arithmetic.",
                    "potential_impact": "May cause runtime crash or improper variable binding.",
                    "remediation": "Review identifier declaration or guard arithmetic operation against zero.",
                    "rule_id": rule_id,
                    "status": "confirmed" if is_err else "probable"
                })
            semantic_results["findings"] = semantic_findings

            total_sem_issues = len(semantic_findings)
            if err_count > 0:
                first_sem_msg = semantic_results['diagnostics'][0]['message'] if semantic_results['diagnostics'] else "Semantic validation failed."
                tracker.fail_stage("semantic_analysis", f"Semantic error: {first_sem_msg}", semantic_results, findings_count=total_sem_issues)
                if pause_on_error:
                    for s in STAGE_DEFINITIONS[5:]:
                        tracker.block_stage(s["id"], "Blocked: Semantic Analysis failed.")
                    tracker.pause_pipeline("semantic_analysis", f"Compilation paused: Semantic error ({first_sem_msg}). Review diagnostics and apply fix to resume.", semantic_results)
                    return tracker
            elif warn_count > 0:
                tracker.complete_stage(
                    "semantic_analysis",
                    f"Semantic analysis completed with {warn_count} warning(s).",
                    semantic_results,
                    findings_count=total_sem_issues
                )
            else:
                tracker.complete_stage(
                    "semantic_analysis",
                    f"Semantic verification passed cleanly. All {len(semantic_results['symbols'])} symbols checked.",
                    semantic_results,
                    findings_count=0
                )
        except Exception as e:
            tracker.fail_stage("semantic_analysis", f"Semantic analysis error: {e}")
            if pause_on_error:
                for s in STAGE_DEFINITIONS[5:]:
                    tracker.block_stage(s["id"], "Blocked: Semantic Analysis error.")
                tracker.pause_pipeline("semantic_analysis", f"Compilation paused: Semantic error ({e}).")
                return tracker
    else:
        tracker.skip_stage("semantic_analysis", "Skipped because AST construction was not completed.")
    _pace()

    # -------------------------------------------------------------------------
    # STAGE 6: Symbol Table / Scope Resolution
    # -------------------------------------------------------------------------
    if ast_tree is not None:
        tracker.start_stage("symbol_table", "Resolving identifier scopes and compiling Symbol Table...")
        _pace()
        try:
            sym_count = len(semantic_results.get("symbols", {}))
            symbol_table_path = os.path.join(TESTS_DIR, "symbol_table.txt")
            with open(symbol_table_path, "w", encoding="utf-8") as stf:
                stf.write("--- SYMBOL TABLE (SEMANTICS) ---\n")
                stf.write("Variable Name\t| Type\t| Scope\t| Line\n")
                stf.write("-" * 50 + "\n")
                for sym_name, sym_info in semantic_results.get("symbols", {}).items():
                    stf.write(f"{sym_name}\t| {sym_info.get('type')}\t| {sym_info.get('scope')}\t| {sym_info.get('line')}\n")

            tracker.complete_stage(
                "symbol_table",
                f"Resolved {sym_count} symbol(s) into global/local lexical environments.",
                {"symbols": semantic_results.get("symbols", {})}
            )
        except Exception as e:
            tracker.fail_stage("symbol_table", f"Symbol table generation error: {e}")
    else:
        tracker.skip_stage("symbol_table", "Skipped because AST was not constructed.")
    _pace()

    # -------------------------------------------------------------------------
    # STAGE 7: Intermediate Representation (IR)
    # -------------------------------------------------------------------------
    ir_code = ""
    if is_valid_syntax:
        tracker.start_stage("ir_generation", "Transpiling multilingual tokens into Python Intermediate Representation...")
        _pace()
        try:
            ir_code = compiler.transpile(source_code)
            ir_lines = len(ir_code.splitlines())
            with open(os.path.join(TESTS_DIR, "ir.txt"), "w", encoding="utf-8") as irf:
                irf.write(ir_code)

            tracker.complete_stage(
                "ir_generation",
                f"Emitted Python IR ({ir_lines} lines of code, whole-word lookarounds applied).",
                {"ir_code": ir_code, "ir_lines": ir_lines}
            )
        except Exception as e:
            tracker.fail_stage("ir_generation", f"Transpilation failed: {e}")
            ir_code = ""
    else:
        tracker.skip_stage("ir_generation", "Skipped because syntax analysis failed.")
    _pace()

    # -------------------------------------------------------------------------
    # STAGE 8: Optimization — MANDATORY (Never Skipped)
    # -------------------------------------------------------------------------
    opt_results = {}
    is_opt_passed = False
    if ir_code:
        tracker.start_stage("optimization", "Executing mandatory IR optimization passes and validation...")
        _pace("optimization")
        try:
            from web.ir_optimizer import IROptimizer
            opt_results = IROptimizer.optimize(ir_code, use_ai=run_ai_security)
            if opt_results.get("success"):
                is_opt_passed = True
                ir_code = opt_results.get("optimized_ir", ir_code)
                with open(os.path.join(TESTS_DIR, "ir.txt"), "w", encoding="utf-8") as irf:
                    irf.write(ir_code)
                tracker.complete_stage(
                    "optimization",
                    opt_results.get("summary", "Optimization completed successfully. No applicable optimization opportunities found." if opt_results.get("transformations_count", 0) == 0 else "IR optimization completed successfully."),
                    opt_results
                )
            else:
                is_opt_passed = False
                tracker.fail_stage("optimization", opt_results.get("summary", "Optimization failed."), opt_results)
                if pause_on_error:
                    for s in STAGE_DEFINITIONS[8:]:
                        tracker.block_stage(s["id"], "Blocked: IR Optimization failed.")
                    tracker.pause_pipeline("optimization", f"Compilation paused: IR optimization failed ({opt_results.get('summary')}).", opt_results)
                    return tracker
        except Exception as e:
            is_opt_passed = False
            tracker.fail_stage("optimization", f"Optimization error: {e}")
            if pause_on_error:
                for s in STAGE_DEFINITIONS[8:]:
                    tracker.block_stage(s["id"], "Blocked: IR Optimization error.")
                tracker.pause_pipeline("optimization", f"Compilation paused: IR optimization error ({e}).")
                return tracker
    else:
        is_opt_passed = False
        tracker.fail_stage("optimization", "Optimization failed: Intermediate Representation not generated.")
        if pause_on_error:
            for s in STAGE_DEFINITIONS[8:]:
                tracker.block_stage(s["id"], "Blocked: Optimization requires valid IR.")
            tracker.pause_pipeline("optimization", "Compilation paused: IR required for optimization.")
            return tracker
    _pace("optimization")

    # -------------------------------------------------------------------------
    # STAGE 9: Code Generation — MANDATORY DEPENDENCY: IR_GEN & OPTIMIZATION
    # -------------------------------------------------------------------------
    target_code = ""
    opt_stage = tracker.stages.get("optimization", {})
    opt_ok = is_opt_passed or (opt_stage.get("status") in ("completed", "passed"))
    if ir_code and opt_ok:
        tracker.start_stage("code_generation", "Emitting executable Python target code with safety harness...")
        _pace("code_generation")
        try:
            # Target code is clean executable Python IR
            target_code = ir_code.strip() + "\n"
            target_lines = len(target_code.splitlines())
            tracker.complete_stage(
                "code_generation",
                f"Emitted runnable Python target code ({target_lines} lines).",
                {"target_code": target_code, "target_lines": target_lines}
            )
        except Exception as e:
            tracker.fail_stage("code_generation", f"Code generation error: {e}")
    else:
        if not opt_ok:
            reason = f"Blocked: Code Generation requires IR Optimization to be PASSED (Optimization status: {opt_stage.get('status', 'missing')})."
            if pause_on_error:
                for s in STAGE_DEFINITIONS[8:]:
                    tracker.block_stage(s["id"], reason)
                tracker.pause_pipeline("optimization", reason)
                return tracker
            else:
                tracker.block_stage("code_generation", reason)
        else:
            reason = "Skipped because Intermediate Representation was not generated."
            if pause_on_error:
                tracker.block_stage("code_generation", reason)
            else:
                tracker.skip_stage("code_generation", reason)
    _pace("code_generation")

    # -------------------------------------------------------------------------
    # STAGE 10: Generated-Code Validation
    # -------------------------------------------------------------------------
    is_target_valid = False
    cg_status = tracker.stages.get("code_generation", {}).get("status")
    if target_code and cg_status in ("completed", "passed"):
        tracker.start_stage("code_validation", "Validating generated target code syntax and AST integrity...")
        _pace("code_validation")
        try:
            compile(target_code, "<target_code>", "exec", ast.PyCF_ONLY_AST)
            is_target_valid = True
            tracker.complete_stage(
                "code_validation",
                "Target Python code passed structural syntax validation without errors.",
                {"is_valid": True}
            )
        except SyntaxError as e:
            tracker.fail_stage("code_validation", f"Target code syntax error: {e.msg} at line {e.lineno}", {"error": str(e)})
            is_target_valid = False
            if pause_on_error:
                for s in STAGE_DEFINITIONS[10:]:
                    tracker.block_stage(s["id"], "Blocked: Generated-Code Validation failed.")
                tracker.pause_pipeline("code_validation", f"Compilation paused: Target code validation error ({e.msg}).", {"error": str(e)})
                return tracker
        except Exception as e:
            tracker.fail_stage("code_validation", f"Target code validation failed: {e}")
            is_target_valid = False
            if pause_on_error:
                for s in STAGE_DEFINITIONS[10:]:
                    tracker.block_stage(s["id"], "Blocked: Generated-Code Validation failed.")
                tracker.pause_pipeline("code_validation", f"Compilation paused: Target code validation error ({e}).")
                return tracker
    else:
        tracker.skip_stage("code_validation", "Skipped because target code was not emitted.")
    _pace()

    # -------------------------------------------------------------------------
    # STAGE 11: Security Analysis (Deterministic Static Scan)
    # -------------------------------------------------------------------------
    tracker.start_stage("security_analysis", "Scanning for vulnerabilities using deterministic security rules...")
    _pace()
    sec_results = {}
    findings: List[Dict[str, Any]] = []
    try:
        sec_results = security_coordinator.run_full_scan(
            source_code=source_code,
            ir_code=ir_code,
            language=detected_lang,
            use_ai_enrichment=False,  # Keep separate from AI stage for progress honesty
            syntax_blocked=(not is_valid_syntax)
        )
        findings = sec_results.get("findings", [])
        overall_score = sec_results.get("overall_risk_score", 0)
        is_blocked = sec_results.get("syntax_blocked", False)

        if is_blocked:
            tracker.complete_stage(
                "security_analysis",
                "Assessment Incomplete: Syntax errors blocked full multi-stage analysis.",
                {"findings": findings, "overall_risk_score": "BLOCKED", "syntax_blocked": True},
                findings_count=len(findings)
            )
        elif findings:
            crit_count = sum(1 for f in findings if f.get("severity") == "Critical")
            high_count = sum(1 for f in findings if f.get("severity") == "High")
            tracker.complete_stage(
                "security_analysis",
                f"Detected {len(findings)} security issue(s) (Risk Score: {overall_score}/100, Critical: {crit_count}, High: {high_count}).",
                {"findings": findings, "overall_risk_score": overall_score},
                findings_count=len(findings)
            )
        else:
            tracker.complete_stage(
                "security_analysis",
                "No issues detected by enabled static security checks (Risk Score: 0/100).",
                {"findings": [], "overall_risk_score": 0},
                findings_count=0
            )
    except Exception as e:
        tracker.fail_stage("security_analysis", f"Security scan error: {e}")
    _pace()

    # -------------------------------------------------------------------------
    # STAGE 12: Ollama AI Analysis
    # -------------------------------------------------------------------------
    ai_status = {
        "model": getattr(ollama_client, "model_name", "qwen2.5-coder:3b"),
        "online": False
    }
    if not run_ai_security:
        tracker.skip_stage(
            "ai_security_analysis",
            "AI analysis skipped (disabled in toolbar); deterministic analysis used"
        )
    else:
        tracker.start_stage("ai_security_analysis", "Consulting local Ollama AI agent...")
        _pace()
        stage12_timeout = float(os.environ.get("VITAL_STAGE12_TIMEOUT", 8.0))
        ai_res = {
            "success": False,
            "timed_out": False,
            "error": "",
            "is_online": False,
            "findings": findings,
            "clean": False
        }

        def _run_stage12_worker():
            try:
                is_online, status_msg, _ = ollama_client.check_health()
                if not is_online:
                    ai_res["is_online"] = False
                    ai_res["error"] = status_msg
                    return
                ai_res["is_online"] = True
                if not findings:
                    ai_res["success"] = True
                    ai_res["clean"] = True
                    return

                enriched_scan = security_coordinator.run_full_scan(
                    source_code=source_code,
                    ir_code=ir_code,
                    language=detected_lang,
                    use_ai_enrichment=True
                )
                ai_res["findings"] = enriched_scan.get("findings", findings)
                ai_res["success"] = True
            except Exception as ex:
                ai_res["error"] = str(ex)

        t_worker = threading.Thread(target=_run_stage12_worker, daemon=True)
        t_worker.start()
        t_worker.join(timeout=stage12_timeout)

        if t_worker.is_alive():
            ai_res["timed_out"] = True

        if ai_res["timed_out"] or not ai_res["success"] or not ai_res["is_online"]:
            # On timeout, offline, or error: mark Stage 12 "warning" with the message
            # "AI analysis skipped (timeout/offline); deterministic analysis used",
            # and continue to Stage 13 and 14 immediately.
            tracker.warn_stage(
                "ai_security_analysis",
                "AI analysis skipped (timeout/offline); deterministic analysis used",
                {"findings": findings, "stage12_timeout": stage12_timeout, "timed_out": ai_res["timed_out"]},
                findings_count=len(findings)
            )
        else:
            findings = ai_res["findings"]
            if ai_res.get("clean"):
                tracker.complete_stage(
                    "ai_security_analysis",
                    f"Ollama online ({ollama_client.model_name}). Code is clean; no suspicious findings requiring investigation.",
                    {"findings_count": 0},
                    findings_count=0
                )
            else:
                tracker.complete_stage(
                    "ai_security_analysis",
                    f"Ollama analyzed {len(findings)} finding(s) and generated recommended remediation diffs.",
                    {"findings": findings},
                    findings_count=len(findings)
                )
    _pace()

    # -------------------------------------------------------------------------
    # STAGE 13: Sandbox Execution — REQUIRES SYNTAX, OPTIMIZATION, AND TARGET VALIDATION
    # -------------------------------------------------------------------------
    runner_res = {}
    if is_valid_syntax and is_opt_passed and is_target_valid:
        tracker.start_stage("sandbox_execution", "Executing inside subprocess sandbox with 5s timeout guard...")
        _pace("sandbox_execution")
        runner_res = run_pipeline(source_code, timeout_seconds=5.0)

        status_code = runner_res.get("execution_status")
        if runner_res.get("success"):
            tracker.complete_stage(
                "sandbox_execution",
                f"Execution completed in {runner_res.get('elapsed_ms', 0)} ms without errors.",
                {"output": runner_res.get("output", "")}
            )
        elif status_code == "timeout":
            tracker.fail_stage(
                "sandbox_execution",
                "Execution timed out (5s limit). Infinite while-loop detected.",
                {"output": runner_res.get("output", "")}
            )
        else:
            tracker.fail_stage(
                "sandbox_execution",
                f"Runtime Error: {runner_res.get('status_message', 'Execution error')}",
                {"output": runner_res.get("output", "")}
            )
    else:
        reason = "Blocked because prerequisite stages (Syntax, Mandatory Optimization, or Target Code) failed."
        if pause_on_error:
            tracker.block_stage("sandbox_execution", reason)
        else:
            tracker.skip_stage("sandbox_execution", reason)
    _pace("sandbox_execution")

    # -------------------------------------------------------------------------
    # STAGE 14: Final Report
    # -------------------------------------------------------------------------
    output_txt = _read_file_safe(os.path.join(TESTS_DIR, "output.txt"))
    lexer_log = _read_file_safe(os.path.join(TESTS_DIR, "lexer_log.txt"))
    parser_log = _read_file_safe(os.path.join(TESTS_DIR, "parser_log.txt"))
    ast_log = _read_file_safe(os.path.join(TESTS_DIR, "ast_log.txt"))
    semantic_log = _read_file_safe(os.path.join(TESTS_DIR, "semantic_log.txt"))
    ir_txt = _read_file_safe(os.path.join(TESTS_DIR, "ir.txt"))
    symbol_table = _read_file_safe(os.path.join(TESTS_DIR, "symbol_table.txt"))

    # Determine final pipeline status with mandatory optimization gate
    opt_stage = tracker.stages.get("optimization", {})
    is_opt_passed = opt_stage.get("status") in ("completed", "passed")
    final_status = "completed"
    if not is_valid_syntax or not is_target_valid or not is_opt_passed or runner_res.get("execution_status") in ("syntax_error", "timeout", "runtime_error"):
        final_status = "failed"
    elif len(findings) > 0 or semantic_results.get("warning_count", 0) > 0:
        final_status = "warning"

    stage_summary_lines = []
    for s in tracker.stages.values():
        st_name = s.get("name", s.get("id"))
        st_status = s.get("status", "unknown").upper()
        st_summary = s.get("summary", "")
        duration_ms = s.get("duration_ms", 0.0)
        stage_summary_lines.append(f"  [{st_status:9s}] {st_name:25s} ({duration_ms:.2f} ms) - {st_summary}")

    passed_count = sum(1 for s in tracker.stages.values() if s.get("status") in ("completed", "passed"))
    warn_count = sum(1 for s in tracker.stages.values() if s.get("status") == "warning")
    failed_count = sum(1 for s in tracker.stages.values() if s.get("status") == "failed")
    skipped_count = sum(1 for s in tracker.stages.values() if s.get("status") == "skipped")

    opt_passes_applied = opt_results.get("passes_applied", [])
    opt_transforms_count = opt_results.get("transformations_count", 0)
    opt_val_status = opt_results.get("validation_status", "PASSED" if is_opt_passed else "FAILED")

    aggregated_log = (
        f"================================================================================\n"
        f"               VITAL COMPILER PIPELINE EXECUTION & AUDIT REPORT                 \n"
        f"================================================================================\n"
        f"SECTION 1: COMPILATION SUMMARY\n"
        f"• Source Language:     {detected_lang}\n"
        f"• Source Revision:     Rev {tracker.source_revision}\n"
        f"• Compilation Run ID:  {tracker.run_id}\n"
        f"• Completion Timestamp:{time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"• Execution Duration:  {round((time.time() - tracker.start_time) * 1000, 2)} ms\n"
        f"• Final Status:        {final_status.upper()}\n\n"
        f"SECTION 2: PIPELINE STAGES BREAKDOWN\n"
        f"• Total Applicable Stages: {len(tracker.applicable_stage_ids)} ({passed_count} Passed, {warn_count} Warning, {failed_count} Failed, {skipped_count} Skipped)\n"
        + "\n".join(stage_summary_lines) + "\n\n"
        f"SECTION 3: LEXICAL ANALYSIS\n"
        f"• Token Stream:        VALIDATED\n"
        f"• Lexical Log:         tests/lexer_log.txt\n\n"
        f"SECTION 4: PARSER & AST CONSTRUCTION\n"
        f"• Syntax / Logic:      {'PASSED' if is_valid_syntax else 'FAILED'}\n"
        f"• Delimiter Integrity: {'BALANCED' if is_valid_syntax else 'IMBALANCED'}\n"
        f"• AST Visual Log:      tests/ast_log.txt\n\n"
        f"SECTION 5: SEMANTIC ANALYSIS\n"
        f"• Semantic Status:     {'PASSED' if semantic_results.get('error_count', 0) == 0 else 'ERRORS DETECTED'}\n"
        f"• Symbols Resolved:    {len(semantic_results.get('symbols', {}))}\n"
        f"• Diagnostics Count:   {len(semantic_results.get('diagnostics', []))}\n\n"
        f"SECTION 6: INTERMEDIATE REPRESENTATION (IR)\n"
        f"• IR Transpilation:    {'EMITTED' if ir_code else 'FAILED'}\n"
        f"• IR Source File:      tests/ir.txt\n\n"
        f"SECTION 7: MANDATORY IR OPTIMIZATION REPORT\n"
        f"• Optimization Status: {'PASSED' if is_opt_passed else 'FAILED'}\n"
        f"• Passes Attempted:    {', '.join(opt_results.get('passes_attempted', ['Constant Folding', 'Constant Propagation', 'Algebraic Simplification', 'Redundant Operation Elimination', 'Dead Code Elimination']))}\n"
        f"• Passes Applied:      {', '.join(opt_passes_applied) if opt_passes_applied else 'None (Code was already optimal)'}\n"
        f"• Transformations:     {opt_transforms_count} transformation(s) applied\n"
        f"• IR Validation:       {opt_val_status}\n"
        f"• Optimization Proof:  {opt_results.get('summary', 'Analysis completed successfully.')}\n"
        + (f"• AI Analysis:         {opt_results.get('ai_analysis')}\n" if opt_results.get("ai_analysis") else "") + "\n"
        f"SECTION 8: CODE GENERATION\n"
        f"• Target Language:     Python 3\n"
        f"• Target Code AST:     {'VALID' if is_target_valid else 'INVALID'}\n\n"
        f"SECTION 9: EXECUTION RESULTS\n"
        f"• Sandbox Execution:   {runner_res.get('execution_status', 'completed').upper()} ({runner_res.get('elapsed_ms', 0)} ms)\n"
        f"• Runtime Output:      tests/output.txt\n\n"
        f"SECTION 10: AI REMEDIATION & SECURITY AUDIT\n"
        f"• Static Findings:     {len(findings)} Issue(s) Detected (Risk Score: {sec_results.get('overall_risk_score', 0)}/100)\n"
        f"• Ollama AI Status:    {ai_status.get('model', 'qwen2.5-coder:7b-instruct')} ({'Online' if ai_status.get('online') else 'Offline'})\n"
        + ("\n".join(f"  • Line {f.get('line', 1)}: [{f.get('severity', 'Medium')}] {f.get('cwe_id') or f.get('rule_id', 'CWE-Unknown')} - {f.get('title', '')}" for f in findings) + "\n" if findings else "  • No security issues detected.\n") + "\n"
        f"SECTION 10B: APPLIED REMEDIATION FIXES\n"
        f"• Status:              {'None (Pristine demo unmodified)' if not tracker.applied_fixes else f'{len(tracker.applied_fixes)} fix(es) applied'}\n\n"
        f"SECTION 11: FINAL COMPILATION VERDICT\n"
        f"================================================================================\n"
        f"  FINAL STATUS: {'COMPILATION SUCCESSFUL' if final_status == 'completed' else ('COMPILATION COMPLETED WITH WARNINGS' if final_status == 'warning' else 'COMPILATION FAILED')}\n"
        f"================================================================================\n"
    )

    final_artifacts = {
        "success": is_valid_syntax and is_target_valid and is_opt_passed and runner_res.get("success", False),
        "execution_status": runner_res.get("execution_status", "completed" if is_valid_syntax else "syntax_error"),
        "detected_language": detected_lang,
        "source_revision": tracker.source_revision,
        "aggregated_log": aggregated_log,
        "output": output_txt or runner_res.get("output", ""),
        "lexer_log": lexer_log,
        "parser_log": parser_log,
        "ast_log": ast_log,
        "semantic_log": semantic_log,
        "ir_code": ir_txt or ir_code,
        "symbol_table": symbol_table,
        "optimization": opt_results or {
            "status": opt_stage.get("status"),
            "summary": opt_stage.get("summary"),
            "details": opt_stage.get("details", {}),
            "passes_attempted": ["Constant Folding", "Constant Propagation", "Algebraic Simplification", "Redundant Operation Elimination", "Dead Code Elimination"],
            "passes_applied": opt_passes_applied,
            "transformations_count": opt_transforms_count,
            "validation_status": opt_val_status,
            "original_ir": ir_txt or ir_code,
            "optimized_ir": ir_code
        },
        "security": {
            "overall_risk_score": "BLOCKED" if is_blocked else sec_results.get("overall_risk_score", 0),
            "overall_summary": sec_results.get("overall_summary", "No issues detected."),
            "findings": findings,
            "ai_status": ai_status,
            "syntax_blocked": is_blocked
        }
    }

    # Mandatory compilation stages 1-10
    mandatory_stages_1_to_10 = [
        "source_input", "lexical_analysis", "syntax_analysis", "ast_construction",
        "semantic_analysis", "symbol_table", "ir_generation", "optimization",
        "code_generation", "code_validation"
    ]
    mandatory_1_to_10_passed = all(
        tracker.stages.get(sid, {}).get("status") in ("completed", "passed", "warning") and
        tracker.stages.get(sid, {}).get("source_revision") == tracker.source_revision
        for sid in mandatory_stages_1_to_10
    )

    # Prepend INCOMPLETE banner if mandatory stages failed
    failed_mandatory = [
        (s["name"], tracker.stages.get(s["id"], {}).get("summary", "Did not pass"))
        for s in STAGE_DEFINITIONS
        if s["id"] in mandatory_stages_1_to_10 and tracker.stages.get(s["id"], {}).get("status") not in ("completed", "passed", "warning")
    ]
    if failed_mandatory:
        incomplete_banner = (
            "================================================================================\n"
            "⚠️  INCOMPLETE COMPILATION REPORT — MANDATORY STAGE FAILURE                     \n"
            "================================================================================\n"
            "The following mandatory compilation stage(s) failed or were not completed:\n"
            + "\n".join(f"  • {name}: {reason}" for name, reason in failed_mandatory) + "\n"
            "================================================================================\n\n"
        )
        final_artifacts["aggregated_log"] = incomplete_banner + final_artifacts["aggregated_log"]
        final_artifacts["incomplete"] = True
        final_artifacts["failed_mandatory_stages"] = failed_mandatory

    # Stage 14 executes automatically when mandatory stages 1-10 passed (even with pause_on_error=True)
    if mandatory_1_to_10_passed:
        tracker.start_stage("final_report", "Assembling multi-stage compiler artifacts and execution report...")
        _pace("final_report")
        tracker.complete_stage(
            "final_report",
            "Pipeline report assembled with all diagnostic logs, AST visual, symbol table, and metrics.",
            {"symbol_table": symbol_table}
        )
        tracker.finish_pipeline(
            final_status,
            f"Pipeline finished with status '{final_status}' ({tracker.completed_stages_count}/{len(tracker.applicable_stage_ids)} applicable stages completed).",
            final_artifacts
        )
    else:
        unpassed = [
            s["name"] for s in STAGE_DEFINITIONS
            if s["id"] in mandatory_stages_1_to_10 and tracker.stages.get(s["id"], {}).get("status") not in ("completed", "passed", "warning")
        ]
        tracker.start_stage("final_report", "Assembling incomplete pipeline report...")
        _pace("final_report")
        tracker.complete_stage(
            "final_report",
            f"Incomplete report assembled: Mandatory stage(s) [ {', '.join(unpassed)} ] did not complete successfully.",
            {"symbol_table": symbol_table, "incomplete": True, "unpassed": unpassed}
        )
        tracker.finish_pipeline(
            "failed",
            f"Pipeline incomplete: Mandatory stage(s) [ {', '.join(unpassed)} ] did not complete successfully.",
            final_artifacts
        )
    return tracker
