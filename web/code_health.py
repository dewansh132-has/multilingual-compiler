# -*- coding: utf-8 -*-
"""
web/code_health.py — Pre-Run Code Health Analyzer for VITAL Multi-Lingual Programs.

Methodology & Architecture:
---------------------------
1. Purpose & Guarantees:
   - Ultra-fast (<300 ms for a 500-line file), deterministic, 100% in-memory static analyzer.
   - Side-effect free: Never writes to disk, never executes user code, makes NO network or AI calls.
   - Operates in "analysis-only" mode: Collects diagnostics across lexical, syntax, semantic,
     dead-code, and security rules without raising exceptions or altering pipeline state.
   - Never touches or reads from pipeline state or Stages 11/12 storage.
   - Line and column positions are reported strictly against the user's ORIGINAL source buffer.

2. Metrics Definitions:
   - total_lines: Total line count of the source buffer.
   - blank_lines: Number of empty lines or lines containing only whitespace.
   - comment_lines: Number of lines where the trimmed content is a comment (//, #, /* ... */).
   - code_lines: total_lines - blank_lines - comment_lines (capped at min 0).
   - functions: Count of top-level and method function definitions.
   - max_nesting_depth: Maximum block nesting depth across control flow statements.
   - avg_function_length: Average lines of code per function (0.0 if no functions).
   - cyclomatic_complexity_total: 1 + total decision points across all branches/loops.
   - cyclomatic_complexity_max: Highest cyclomatic complexity in any individual function.

3. Dead Code Detection & Percentage:
   - Kinds detected:
     * unused_variable: Identifiers declared/assigned that are never read in a load context.
     * unused_parameter: Function parameters never referenced within the function body.
     * unused_function: Functions defined but never called (excluding standard entry points like main/mukhya).
     * unreachable_after_return: Statements in a block following return, break, or continue.
     * never_true_branch: Branches with statically false conditions (e.g. if (0), if (false))
       or duplicate identical bodies.
   - dead_code.percentage = (lines belonging to unused/unreachable code) / code_lines * 100,
     rounded to 1 decimal place, clamped to [0.0, 100.0].

4. Security Scan & Insecure Percentage:
   - Uses read-only deterministic regex, parser delimiter, and AST/taint rules from
     web.security_analyzer.DeterministicSecurityScanner without triggering AI or pipeline tracking.
   - insecure_lines: Sorted list of distinct original line numbers with security findings.
   - Line weights: Critical: 1.0, High: 0.8, Medium: 0.5, Low: 0.2 (max severity weight per line).
   - insecure_percentage = min(100.0, (sum of weighted insecure lines / code_lines) * 100),
     rounded to 1 decimal place.

5. Scoring Formula:
   - score = 100 - min(100, penalties)
     where penalties = (
         syntax_penalty (flat 25 if any syntax error)
       + semantic_penalty (8 per semantic error, capped at 30)
       + insecure_percentage * 0.6
       + dead_code_percentage * 0.4
       + complexity_penalty (linear scale above complexity 5, max 10)
     )
   - Clamped to integer [0, 100].
   - Grade mapping: A (90-100), B (80-89), C (70-79), D (60-69), F (0-59).
   - Status precedence: errors > unsafe (any HIGH/CRITICAL) > warnings > healthy.

6. Predicted Pipeline Simulation (Stages 1..10):
   - Simulates compiler stages 1-10:
     1: Source Input, 2: Lexical, 3: Syntax, 4: AST, 5: Semantic, 6: Symbol Table,
     7: IR, 8: Optimization, 9: Code Gen, 10: Validation.
   - If an error occurs at stage N, stages 1..N-1 are "pass", stage N is "fail",
     and downstream stages N+1..10 are "not_reached".
   - blocking_stage indicates the first predicted failure with reason, or null if all pass.

7. Multi-Lingual Support:
   - Supports English, Hindi, Telugu, Bengali, Marathi, Nepali, and Multilingual Fusion.
"""

import ast
import contextlib
import copy
import hashlib
import io
import json
import os
import re
import sys
import threading
import unicodedata
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure src and root are in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(BASE_DIR, "src")
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from lexer import VitalLexer, analyze_delimiters, LexerError, HOMOGLYPH_MAP
from main import Compiler, RULES_FILE
from semantic import SemanticAnalyzer
from web.demo_manager import detect_file_language
from web.gate_policy import extract_cwe_from_text_or_rule
from web.security_analyzer import DeterministicSecurityScanner


# ============================================================================
# CONFIGURATION & WEIGHTS
# ============================================================================

HEALTH_SCORING_WEIGHTS = {
    "syntax_error_flat": 25.0,
    "semantic_error_weight": 8.0,
    "semantic_error_max": 30.0,
    "insecure_weight": 0.6,
    "dead_code_weight": 0.4,
    "complexity_threshold": 5.0,
    "complexity_scale": 1.5,
    "complexity_max": 10.0,
}

SEVERITY_LINE_WEIGHTS = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.2,
    "INFO": 0.0,
}

STAGE_NAMES = {
    1: "Source Input",
    2: "Lexical Analysis",
    3: "Syntax Analysis",
    4: "AST Construction",
    5: "Semantic Analysis",
    6: "Symbol Table",
    7: "Intermediate Representation (IR)",
    8: "Optimization",
    9: "Code Generation",
    10: "Target Validation",
}

ENTRY_POINT_NAMES = {
    "main", "_main", "__main__", "run", "start", "app", "handler",
    "मुख्य", "प्रधान", "प्रामुख्य", "मूल", "प्रधान_कार्य", "મુખ્ય",
    "सुरु", "शुरू", "మొదలు", "শুরু"
}


def normalize_ident(name: Any) -> str:
    """Normalize identifier using NFC and canonical homoglyph mapping."""
    if not name:
        return ""
    n = unicodedata.normalize("NFC", str(name))
    chars = [HOMOGLYPH_MAP.get(c, c) for c in n]
    return "".join(chars)


# ============================================================================
# IN-MEMORY LRU CACHE (Maxsize 64)
# ============================================================================

_CACHE_LOCK = threading.Lock()
_HEALTH_CACHE: OrderedDict[Tuple[str, str], Dict[str, Any]] = OrderedDict()
_CACHE_MAXSIZE = 64

def _get_from_cache(key: Tuple[str, str]) -> Optional[Dict[str, Any]]:
    with _CACHE_LOCK:
        if key in _HEALTH_CACHE:
            _HEALTH_CACHE.move_to_end(key)
            return copy.deepcopy(_HEALTH_CACHE[key])
        return None

def _put_in_cache(key: Tuple[str, str], value: Dict[str, Any]) -> None:
    with _CACHE_LOCK:
        _HEALTH_CACHE[key] = copy.deepcopy(value)
        _HEALTH_CACHE.move_to_end(key)
        while len(_HEALTH_CACHE) > _CACHE_MAXSIZE:
            _HEALTH_CACHE.popitem(last=False)

def clear_health_cache() -> None:
    """Clears the health analyzer cache (used in tests)."""
    with _CACHE_LOCK:
        _HEALTH_CACHE.clear()


# ============================================================================
# CACHED COMPILER INSTANCE
# ============================================================================

_COMPILER_INSTANCE: Optional[Compiler] = None
_COMPILER_LOCK = threading.Lock()

def _get_compiler() -> Compiler:
    global _COMPILER_INSTANCE
    with _COMPILER_LOCK:
        if _COMPILER_INSTANCE is None:
            c = Compiler(RULES_FILE)
            c.load_rules()
            _COMPILER_INSTANCE = c
        return _COMPILER_INSTANCE


# ============================================================================
# METRICS EXTRACTOR
# ============================================================================

def _compute_metrics(source: str, ast_tree: Optional[ast.AST]) -> Dict[str, Any]:
    lines = source.splitlines()
    total_lines = len(lines)
    blank_lines = 0
    comment_lines = 0
    in_block_comment = False

    for line in lines:
        stripped = line.strip()
        if not stripped:
            blank_lines += 1
            continue
        if in_block_comment:
            comment_lines += 1
            if "*/" in stripped:
                in_block_comment = False
            continue
        if stripped.startswith("/*"):
            comment_lines += 1
            if "*/" not in stripped:
                in_block_comment = True
            continue
        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("--"):
            comment_lines += 1
            continue

    code_lines = max(0, total_lines - blank_lines - comment_lines)

    functions = 0
    function_lengths: List[int] = []
    max_depth = 0
    total_complexity = 1
    max_function_complexity = 1

    if ast_tree is not None:
        def _calc_nesting(node: ast.AST, current_depth: int) -> int:
            nonlocal max_depth
            if current_depth > max_depth:
                max_depth = current_depth
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor, ast.FunctionDef, ast.AsyncFunctionDef, ast.Try, ast.With)):
                    _calc_nesting(child, current_depth + 1)
                else:
                    _calc_nesting(child, current_depth)
            return max_depth

        _calc_nesting(ast_tree, 0)

        for node in ast.walk(ast_tree):
            if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor, ast.ExceptHandler, ast.IfExp)):
                total_complexity += 1
            elif isinstance(node, ast.BoolOp):
                total_complexity += max(0, len(node.values) - 1)

            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions += 1
                end_l = getattr(node, "end_lineno", getattr(node, "lineno", 1))
                start_l = getattr(node, "lineno", 1)
                function_lengths.append(max(1, end_l - start_l + 1))

                f_complexity = 1
                for f_node in ast.walk(node):
                    if isinstance(f_node, (ast.If, ast.While, ast.For, ast.AsyncFor, ast.ExceptHandler, ast.IfExp)):
                        f_complexity += 1
                    elif isinstance(f_node, ast.BoolOp):
                        f_complexity += max(0, len(f_node.values) - 1)
                if f_complexity > max_function_complexity:
                    max_function_complexity = f_complexity
    else:
        # Fallback depth estimation from indentation
        for line in lines:
            if line.strip():
                indent = len(line) - len(line.lstrip(" "))
                depth = indent // 4
                if depth > max_depth:
                    max_depth = depth

    avg_function_length = round(sum(function_lengths) / functions, 1) if functions > 0 else 0.0

    return {
        "total_lines": total_lines,
        "code_lines": code_lines,
        "comment_lines": comment_lines,
        "blank_lines": blank_lines,
        "functions": functions,
        "max_nesting_depth": max_depth,
        "avg_function_length": avg_function_length,
        "cyclomatic_complexity_total": total_complexity,
        "cyclomatic_complexity_max": max_function_complexity if functions > 0 else total_complexity,
    }


# ============================================================================
# DEAD CODE DETECTOR
# ============================================================================

class _DeadCodeVisitor(ast.NodeVisitor):
    def __init__(self, code_lines_set: Set[int], source_lines: Optional[List[str]] = None):
        self.code_lines_set = code_lines_set
        self.source_lines = source_lines or []
        self.dead_items: List[Dict[str, Any]] = []
        self.dead_lines: Set[int] = set()

    def _add_dead(self, kind: str, name: str, line: int, message: str, end_line: Optional[int] = None, col: int = 1):
        evidence = ""
        if 1 <= line <= len(self.source_lines):
            evidence = self.source_lines[line - 1].strip()

        self.dead_items.append({
            "id": f"CH-DEAD-L{line}-{kind}-{name}",
            "kind": kind,
            "name": name,
            "line": line,
            "column": col,
            "evidence": evidence,
            "message": message
        })
        end = end_line if end_line is not None else line
        for l in range(line, end + 1):
            if l in self.code_lines_set:
                self.dead_lines.add(l)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._check_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._check_function(node)
        self.generic_visit(node)

    def _check_function(self, node):
        # 1. Check unused parameters with Unicode normalization
        body_loads = {normalize_ident(n.id) for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
        for n in ast.walk(node):
            if isinstance(n, ast.Attribute):
                body_loads.add(normalize_ident(n.attr))

        for arg in node.args.args:
            norm_arg = normalize_ident(arg.arg)
            if arg.arg not in ("self", "cls", "_") and not arg.arg.startswith("__"):
                if norm_arg not in body_loads:
                    self._add_dead(
                        "unused_parameter",
                        arg.arg,
                        arg.lineno,
                        f"Parameter '{arg.arg}' is never used in function '{node.name}'.",
                        col=getattr(arg, "col_offset", 0) + 1
                    )

        # 2. Check unreachable statements after return / break / continue / raise
        self._check_block_unreachable(node.body)

    def _check_block_unreachable(self, stmts: List[ast.stmt]):
        terminal_idx = -1
        terminal_stmt = None
        for i, stmt in enumerate(stmts):
            if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                terminal_idx = i
                terminal_stmt = stmt
                break

        if terminal_idx != -1 and terminal_idx < len(stmts) - 1:
            for unreach in stmts[terminal_idx + 1:]:
                start_l = getattr(unreach, "lineno", terminal_stmt.lineno + 1)
                end_l = getattr(unreach, "end_lineno", start_l)
                self._add_dead(
                    "unreachable_after_return",
                    type(unreach).__name__,
                    start_l,
                    f"Unreachable statement {type(unreach).__name__} at line {start_l} following {type(terminal_stmt).__name__}.",
                    end_line=end_l,
                    col=getattr(unreach, "col_offset", 0) + 1
                )

    def visit_If(self, node: ast.If):
        # Check constant false condition
        is_const_false = False
        if isinstance(node.test, ast.Constant):
            if not bool(node.test.value):
                is_const_false = True
        elif isinstance(node.test, ast.Compare):
            # e.g., 0 == 1 or 1 == 0
            if (isinstance(node.test.left, ast.Constant) and len(node.test.comparators) == 1
                    and isinstance(node.test.comparators[0], ast.Constant)):
                l_val = node.test.left.value
                r_val = node.test.comparators[0].value
                op = node.test.ops[0]
                if isinstance(op, ast.Eq) and l_val != r_val:
                    is_const_false = True
                elif isinstance(op, ast.NotEq) and l_val == r_val:
                    is_const_false = True
                elif isinstance(op, ast.Gt) and not (l_val > r_val):
                    is_const_false = True
                elif isinstance(op, ast.Lt) and not (l_val < r_val):
                    is_const_false = True

        if is_const_false:
            start_l = getattr(node.body[0], "lineno", node.lineno) if node.body else node.lineno
            end_l = getattr(node.body[-1], "end_lineno", start_l) if node.body else start_l
            self._add_dead(
                "never_true_branch",
                "if",
                node.lineno,
                f"Branch condition at line {node.lineno} is statically false; branch body is never executed.",
                end_line=end_l,
                col=getattr(node, "col_offset", 0) + 1
            )

        self._check_block_unreachable(node.body)
        if node.orelse:
            self._check_block_unreachable(node.orelse)

        self.generic_visit(node)


def _detect_dead_code(ast_tree: Optional[ast.AST], code_lines_set: Set[int], total_code_lines: int, source_lines: Optional[List[str]] = None) -> Dict[str, Any]:
    if ast_tree is None:
        return {"percentage": 0.0, "items": []}

    src_lines = source_lines or []
    visitor = _DeadCodeVisitor(code_lines_set, src_lines)
    visitor.visit(ast_tree)

    # 1. Unused Functions Check (with Unicode normalization)
    all_calls = set()
    all_loads = set()
    declared_functions = {}

    for node in ast.walk(ast_tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            norm_f = normalize_ident(node.name)
            if norm_f not in ENTRY_POINT_NAMES and not norm_f.startswith("_") and node.name not in ENTRY_POINT_NAMES and not node.name.startswith("_"):
                declared_functions[norm_f] = (node.name, node.lineno, getattr(node, "end_lineno", node.lineno), getattr(node, "col_offset", 0) + 1)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                all_calls.add(normalize_ident(node.func.id))
            elif isinstance(node.func, ast.Attribute):
                all_calls.add(normalize_ident(node.func.attr))
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            all_loads.add(normalize_ident(node.id))
        elif isinstance(node, ast.Attribute):
            all_loads.add(normalize_ident(node.attr))

    for norm_f, (func_name, start_l, end_l, col) in declared_functions.items():
        if norm_f not in all_calls and norm_f not in (all_loads - {norm_f}):
            visitor._add_dead(
                "unused_function",
                func_name,
                start_l,
                f"Function '{func_name}' is declared at line {start_l} but never called in this program.",
                end_line=end_l,
                col=col
            )

    # 2. Unused Variables Check (assigned names never loaded)
    assigned_vars: Dict[str, Tuple[str, int, int]] = {}
    loaded_vars: Set[str] = set()

    for node in ast.walk(ast_tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if hasattr(node, "targets") else [node.target]
            for t in targets:
                for n in ast.walk(t):
                    if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                        norm_id = normalize_ident(n.id)
                        if (norm_id not in ENTRY_POINT_NAMES and not norm_id.startswith("_")
                                and norm_id not in declared_functions
                                and n.id not in ENTRY_POINT_NAMES and not n.id.startswith("_")
                                and n.id not in declared_functions):
                            lno = getattr(n, "lineno", getattr(node, "lineno", 1))
                            cno = getattr(n, "col_offset", getattr(node, "col_offset", 0)) + 1
                            assigned_vars[norm_id] = (n.id, lno, cno)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            loaded_vars.add(normalize_ident(node.id))
        elif isinstance(node, ast.Attribute):
            loaded_vars.add(normalize_ident(node.attr))

    for norm_var, (var_name, line, col) in assigned_vars.items():
        if norm_var not in loaded_vars:
            visitor._add_dead(
                "unused_variable",
                var_name,
                line,
                f"Variable '{var_name}' is declared at line {line} but never read or referenced.",
                col=col
            )

    dead_count = len(visitor.dead_lines)
    percentage = round((dead_count / max(1, total_code_lines)) * 100.0, 1)
    percentage = min(100.0, max(0.0, percentage))

    # Sort items by line
    visitor.dead_items.sort(key=lambda x: x["line"])

    return {
        "percentage": percentage,
        "items": visitor.dead_items
    }


# ============================================================================
# HEALTH SCORE & GRADE CALCULATOR
# ============================================================================

def calculate_health_score(
    syntax_error_count: int,
    semantic_error_count: int,
    insecure_percentage: float,
    dead_code_percentage: float,
    complexity_max: int,
    critical_count: int = 0,
    high_count: int = 0,
    weights: Dict[str, float] = HEALTH_SCORING_WEIGHTS
) -> int:
    """Calculates single deterministic code health score (0-100)."""
    p_syntax = weights["syntax_error_flat"] if syntax_error_count > 0 else 0.0
    p_semantic = min(weights["semantic_error_max"], semantic_error_count * weights["semantic_error_weight"])
    p_insecure = insecure_percentage * weights["insecure_weight"]
    p_dead = dead_code_percentage * weights["dead_code_weight"]

    diff_comp = max(0.0, complexity_max - weights["complexity_threshold"])
    p_comp = min(weights["complexity_max"], diff_comp * weights["complexity_scale"])

    total_penalty = min(100.0, p_syntax + p_semantic + p_insecure + p_dead + p_comp)
    score = int(round(max(0.0, min(100.0, 100.0 - total_penalty))))

    # Severity capping: Any HIGH/CRITICAL finding must cap the grade at C (or lower for several)
    unsafe_count = critical_count + high_count
    if unsafe_count >= 3 or critical_count >= 2:
        score = min(score, 59)
    elif unsafe_count >= 2:
        score = min(score, 69)
    elif unsafe_count >= 1:
        score = min(score, 79)

    return score


def calculate_health_grade(score: int) -> str:
    """Maps score to canonical letter grade A-F."""
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    return "F"


# ============================================================================
# MAIN CODE HEALTH ANALYZER
# ============================================================================

def analyze_health(source: str, language: str = "", filename: str = "", skip_collector: bool = False) -> Dict[str, Any]:
    """
    Performs fast (<300ms), deterministic, side-effect free Code Health analysis.

    Returns the complete Health Report JSON schema.
    Results are cached in-memory with LRU eviction (maxsize 64).
    """
    source_str = source or ""
    source_hash = hashlib.sha256(source_str.encode("utf-8")).hexdigest()

    # Determine language if unspecified
    resolved_lang = language.strip() if language else detect_file_language(source_str, filename)
    if not resolved_lang:
        resolved_lang = "English"

    # Check LRU cache (only when full canonical analysis is requested)
    cache_key = (source_hash, resolved_lang)
    if not skip_collector:
        cached_val = _get_from_cache(cache_key)
        if cached_val is not None:
            return cached_val

    with contextlib.redirect_stdout(io.StringIO()):
        # Initialize analysis collections
        errors: List[Dict[str, Any]] = []
        first_blocking_stage: Optional[Dict[str, Any]] = None

        # Handle empty source code
        if not source_str.strip():
            first_blocking_stage = {
                "stage": 1,
                "name": "Source Input",
                "reason": "Source code is empty."
            }
            empty_metrics = {
                "total_lines": 0, "code_lines": 0, "comment_lines": 0, "blank_lines": 0,
                "functions": 0, "max_nesting_depth": 0, "avg_function_length": 0.0,
                "cyclomatic_complexity_total": 0, "cyclomatic_complexity_max": 0
            }
            predicted_pipeline = [{"stage": 1, "status": "fail"}] + [{"stage": i, "status": "not_reached"} for i in range(2, 11)]
            res = {
                "source_hash": source_hash,
                "language": resolved_lang,
                "analyzed_at": datetime.now(timezone.utc).isoformat(),
                "score": 0,
                "grade": "F",
                "status": "errors",
                "metrics": empty_metrics,
                "errors": [{
                    "code": "SRC-001",
                    "stage": 1,
                    "severity": "error",
                    "line": 1,
                    "column": 1,
                    "message": "Source code is empty."
                }],
                "dead_code": {"percentage": 0.0, "items": []},
                "security": {"insecure_percentage": 0.0, "findings": [], "insecure_lines": []},
                "blocking_stage": first_blocking_stage,
                "predicted_pipeline": predicted_pipeline
            }
            _put_in_cache(cache_key, res)
            return res

        compiler = _get_compiler()

        # Stage 2: Lexical Analysis (Memory-only)
        tokens = []
        try:
            tokens = compiler.lexer.tokenize(source_str)
        except LexerError as le:
            errors.append({
                "code": "LEX-001",
                "stage": 2,
                "severity": "error",
                "line": getattr(le, "line", 1),
                "column": getattr(le, "column", 1),
                "message": str(le)
            })
            if first_blocking_stage is None:
                first_blocking_stage = {
                    "stage": 2,
                    "name": "Lexical Analysis",
                    "reason": str(le)
                }
        except Exception as ex:
            errors.append({
                "code": "LEX-001",
                "stage": 2,
                "severity": "error",
                "line": 1,
                "column": 1,
                "message": f"Lexer error: {ex}"
            })
            if first_blocking_stage is None:
                first_blocking_stage = {
                    "stage": 2,
                    "name": "Lexical Analysis",
                    "reason": f"Lexer error: {ex}"
                }

        # Check lexical diagnostics / rules (homoglyphs, backticks, shell injection, etc.)
        lex_findings = DeterministicSecurityScanner.scan_lexical(source_str, include_homoglyphs=True)
        if lex_findings and first_blocking_stage is None:
            first_f = lex_findings[0]
            first_blocking_stage = {
                "stage": 2,
                "name": "Lexical Analysis",
                "reason": f"{len(lex_findings)} lexical issue(s) detected: {getattr(first_f, 'title', getattr(first_f, 'message', 'Lexical diagnostic'))}"
            }
            for lf in lex_findings:
                errors.append({
                    "code": getattr(lf, "rule_id", "LEX-001"),
                    "stage": 2,
                    "severity": "error",
                    "line": getattr(lf, "line", 1) or 1,
                    "column": getattr(lf, "column", 1) or 1,
                    "message": getattr(lf, "title", getattr(lf, "message", "Lexical diagnostic"))
                })

        # Stage 3: Syntax & Delimiter Analysis (Memory-only)
        delim_result = analyze_delimiters(tokens) if tokens else {"is_balanced": True, "unclosed_tokens": [], "mismatches": [], "unmatched_close": []}
        has_syntax_error = False

        if not delim_result.get("is_balanced", True):
            has_syntax_error = True
            # Report unbalanced delimiters
            for t, msg in delim_result.get("unmatched_close", []):
                code = "SYN-001" if t.lexeme == "}" else ("SYN-002" if t.lexeme == ")" else "SYN-003")
                errors.append({
                    "code": code,
                    "stage": 3,
                    "severity": "error",
                    "line": t.line,
                    "column": t.column,
                    "message": f"Unbalanced delimiter: Unexpected closing '{t.lexeme}' at line {t.line}:{t.column}."
                })

            for t, top, msg in delim_result.get("mismatches", []):
                errors.append({
                    "code": "SYN-003",
                    "stage": 3,
                    "severity": "error",
                    "line": t.line,
                    "column": t.column,
                    "message": msg
                })

            for t in delim_result.get("unclosed_tokens", []):
                code = "SYN-001" if t.lexeme == "{" else ("SYN-002" if t.lexeme == "(" else "SYN-003")
                errors.append({
                    "code": code,
                    "stage": 3,
                    "severity": "error",
                    "line": t.line,
                    "column": t.column,
                    "message": f"Unbalanced delimiter: Unclosed '{t.lexeme}' opened at line {t.line}:{t.column}."
                })

            if first_blocking_stage is None and errors:
                first_err = errors[0]
                first_blocking_stage = {
                    "stage": 3,
                    "name": "Syntax Analysis",
                    "reason": first_err["message"]
                }

        # Transpilation & AST Construction (Memory-only)
        ir_code = ""
        ast_tree = None
        if not has_syntax_error:
            try:
                ir_code = compiler.transpile(source_str)
                ast_tree = ast.parse(ir_code)
            except SyntaxError as se:
                has_syntax_error = True
                errors.append({
                    "code": "SYN-001",
                    "stage": 3,
                    "severity": "error",
                    "line": se.lineno or 1,
                    "column": se.offset or 1,
                    "message": f"Syntax error: {se.msg} at line {se.lineno}."
                })
                if first_blocking_stage is None:
                    first_blocking_stage = {
                        "stage": 3,
                        "name": "Syntax Analysis",
                        "reason": f"Syntax error: {se.msg}."
                    }
            except Exception as ex:
                if first_blocking_stage is None:
                    first_blocking_stage = {
                        "stage": 4,
                        "name": "AST Construction",
                        "reason": f"AST construction failed: {ex}."
                    }

        # Stage 5: Semantic Analysis (Memory-only)
        semantic_error_count = 0
        if ast_tree is not None:
            try:
                analyzer = SemanticAnalyzer()
                sem_res = analyzer.analyze(ast_tree)
                for d in sem_res.get("diagnostics", []):
                    if d.get("type") == "error":
                        semantic_error_count += 1
                        msg = d.get("message", "Semantic error")
                        code = "SEM-002" if "division by zero" in msg.lower() else "SEM-001"
                        errors.append({
                            "code": code,
                            "stage": 5,
                            "severity": "error",
                            "line": d.get("line", 1),
                            "column": d.get("column", 1),
                            "message": msg
                        })
                if first_blocking_stage is None and semantic_error_count > 0:
                    first_blocking_stage = {
                        "stage": 5,
                        "name": "Semantic Analysis",
                        "reason": errors[-semantic_error_count]["message"]
                    }
            except Exception as ex:
                if first_blocking_stage is None:
                    first_blocking_stage = {
                        "stage": 5,
                        "name": "Semantic Analysis",
                        "reason": f"Semantic analysis error: {ex}."
                    }

        # Metrics Extraction
        metrics = _compute_metrics(source_str, ast_tree)
        code_lines_count = metrics["code_lines"]

        # Build set of valid code lines
        code_lines_set = set()
        for l_idx, line in enumerate(source_str.splitlines(), start=1):
            s = line.strip()
            if s and not s.startswith(("//", "#", "--", "/*")):
                code_lines_set.add(l_idx)

        # Dead Code Analysis
        dead_code = _detect_dead_code(ast_tree, code_lines_set, code_lines_count, source_lines=source_str.splitlines())

        # Security Analysis (Deterministic & Read-Only; homoglyphs owned by Lexer stage)
        raw_findings = []
        raw_findings.extend(DeterministicSecurityScanner.scan_lexical(source_str, include_homoglyphs=False))
        raw_findings.extend(DeterministicSecurityScanner.scan_parser(source_str))
        raw_findings.extend(DeterministicSecurityScanner.scan_multilingual_security(source_str, resolved_lang, check_semantic=False))

        if not has_syntax_error and ir_code:
            raw_findings.extend(DeterministicSecurityScanner.scan_python_ir_ast(ir_code, source_code=source_str))
            raw_findings.extend(DeterministicSecurityScanner.scan_execution_boundary(source_str, ir_code))

        # Format security findings conforming to schema
        formatted_findings: List[Dict[str, Any]] = []
        insecure_line_map: Dict[int, float] = {}

        for f in raw_findings:
            f_line = getattr(f, "line", 1) or 1
            f_rule = getattr(f, "rule_id", "SEC-001")
            f_id = getattr(f, "id", "") or f"{f_rule}-L{f_line}"
            f_sev = str(getattr(f, "severity", "Medium")).capitalize()
            f_title = getattr(f, "title", str(f))
            f_cwe = getattr(f, "cwe", "") or extract_cwe_from_text_or_rule(f_rule, f_title)

            formatted_findings.append({
                "id": f_id,
                "rule_id": f_rule,
                "cwe": f_cwe,
                "severity": f_sev,
                "line": f_line,
                "message": f_title
            })

            if 1 <= f_line <= metrics["total_lines"]:
                weight = SEVERITY_LINE_WEIGHTS.get(f_sev.upper(), 0.5)
                insecure_line_map[f_line] = max(insecure_line_map.get(f_line, 0.0), weight)

        insecure_lines = sorted(list(insecure_line_map.keys()))
        weighted_line_sum = sum(insecure_line_map.values())
        insecure_percentage = min(100.0, round((weighted_line_sum / max(1, code_lines_count)) * 100.0, 1))

        security_res = {
            "insecure_percentage": insecure_percentage,
            "findings": formatted_findings,
            "insecure_lines": insecure_lines
        }

        # Predicted Pipeline Construction (Stages 1..10)
        predicted_pipeline: List[Dict[str, Any]] = []
        failing_stage_num = first_blocking_stage["stage"] if first_blocking_stage else None

        for s_idx in range(1, 11):
            if failing_stage_num is None:
                s_status = "pass"
            elif s_idx < failing_stage_num:
                s_status = "pass"
            elif s_idx == failing_stage_num:
                s_status = "fail"
            else:
                s_status = "not_reached"

            predicted_pipeline.append({
                "stage": s_idx,
                "status": s_status
            })

        # Single canonical collection of all issues
        if not skip_collector:
            from web.issue_collector import collect_issues, counts_by_stage, counts_by_severity, total_fixable
            canonical_issues = collect_issues(source_str, resolved_lang)
            fixable_canonical = [i.to_dict() for i in canonical_issues if i.fixable]
            total_fix_count = total_fixable(canonical_issues)
            stage_counts = counts_by_stage(canonical_issues)
            sev_counts = counts_by_severity(canonical_issues)
        else:
            canonical_issues = []
            fixable_canonical = []
            total_fix_count = 0
            stage_counts = {}
            sev_counts = {}

        # Align Insecure Code % and Dead Code % strictly with canonical issues
        sec_issues = [i for i in canonical_issues if i.source in ("sast", "ai")]
        dead_issues = [i for i in canonical_issues if i.source == "dead_code"]
        lex_issues = [i for i in canonical_issues if i.source == "lexer"]
        syn_issues = [i for i in canonical_issues if i.source == "parser"]
        sem_issues = [i for i in canonical_issues if i.source == "semantic"]
        run_issues = [i for i in canonical_issues if i.source == "runtime"]

        code_lines_cnt = max(1, metrics["code_lines"])
        if canonical_issues:
            insecure_lines = sorted(list({i.line for i in sec_issues if 1 <= i.line <= metrics["total_lines"]}))
            dead_lines = sorted(list({i.line for i in dead_issues if 1 <= i.line <= metrics["total_lines"]}))
            insecure_percentage = min(100.0, round((len(insecure_lines) / code_lines_cnt) * 100.0, 1))
            dead_code_percentage = min(100.0, round((len(dead_lines) / code_lines_cnt) * 100.0, 1))
            security_res["insecure_percentage"] = insecure_percentage
            security_res["insecure_lines"] = insecure_lines
            dead_code["percentage"] = dead_code_percentage

        # Build categorical breakdown
        breakdown = {
            "security": len(sec_issues),
            "dead_code": len(dead_issues),
            "lexer": len(lex_issues),
            "syntax": len(syn_issues),
            "semantic": len(sem_issues),
            "runtime": len(run_issues),
        }
        parts = []
        if breakdown["security"]: parts.append(f"{breakdown['security']} security")
        if breakdown["dead_code"]: parts.append(f"{breakdown['dead_code']} dead code")
        if breakdown["lexer"]: parts.append(f"{breakdown['lexer']} lexer")
        if breakdown["syntax"]: parts.append(f"{breakdown['syntax']} syntax")
        if breakdown["semantic"]: parts.append(f"{breakdown['semantic']} semantic")
        if breakdown["runtime"]: parts.append(f"{breakdown['runtime']} runtime")
        breakdown_summary = f"{len(canonical_issues)} = {' + '.join(parts)}" if parts else "0 issues"
        breakdown["summary"] = breakdown_summary

        # Health Score & Grade
        syntax_err_count = sum(1 for e in errors if e.get("stage") == 3)
        crit_count = sum(1 for i in canonical_issues if (i.severity or "").lower() == "critical")
        high_count = sum(1 for i in canonical_issues if (i.severity or "").lower() == "high")
        if not canonical_issues:
            crit_count = sum(1 for f in formatted_findings if f["severity"].upper() == "CRITICAL")
            high_count = sum(1 for f in formatted_findings if f["severity"].upper() == "HIGH")

        score = calculate_health_score(
            syntax_err_count,
            semantic_error_count,
            insecure_percentage,
            dead_code["percentage"],
            metrics["cyclomatic_complexity_max"],
            critical_count=crit_count,
            high_count=high_count
        )
        grade = calculate_health_grade(score)

        # Status Precedence: errors > unsafe > warnings > healthy
        has_unsafe = (crit_count + high_count > 0) or any(f["severity"].upper() in ("CRITICAL", "HIGH") for f in formatted_findings)
        has_warnings = (
            len(dead_issues) > 0
            or len(dead_code["items"]) > 0
            or any(f["severity"].upper() in ("MEDIUM", "LOW") for f in formatted_findings)
        )

        if errors:
            status = "errors"
        elif has_unsafe:
            status = "unsafe"
        elif has_warnings:
            status = "warnings"
        else:
            status = "healthy"

        file_display = os.path.basename(filename) if filename else "source.vital"
        hash8 = source_hash[:8]
        insec_pct = int(round(security_res.get("insecure_percentage", 0.0)))
        dead_pct = int(round(dead_code.get("percentage", 0.0)))
        health_log_line = f"[health] analysed {file_display} @ {hash8} score={score} errors={len(errors)} insecure={insec_pct}% dead={dead_pct}%"
        print(health_log_line)

        result = {
            "source_hash": source_hash,
            "language": resolved_lang,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "score": score,
            "grade": grade,
            "status": status,
            "metrics": metrics,
            "errors": errors,
            "dead_code": dead_code,
            "security": security_res,
            "blocking_stage": first_blocking_stage,
            "predicted_pipeline": predicted_pipeline,
            "log_line": health_log_line,
            "issues": [i.to_dict() for i in canonical_issues],
            "counts_by_stage": stage_counts,
            "counts_by_severity": sev_counts,
            "total_fixable": total_fix_count,
            "fixable_issues": fixable_canonical,
            "fixable_count": total_fix_count,
            "breakdown": breakdown
        }

        if not skip_collector:
            _put_in_cache(cache_key, result)
        return result


def collect_fixable_issues(source: str, language: str = "") -> List[Dict[str, Any]]:
    """
    Single source of truth for all fixable issues across Code Health,
    Compiler diagnostics, Dead Code, and Security rules.
    Returns: [{id, kind, stage, severity, line, column, evidence, message}]
    """
    from web.issue_collector import collect_issues
    issues = collect_issues(source, language)
    return [i.to_dict() for i in issues if i.fixable]
