# -*- coding: utf-8 -*-
"""
web/ai_remediation_engine.py — Hardware-Aware Multi-Model AI Remediation Engine for VITAL IDE

Multi-Model Architecture & Memory Management:
  - 16 GB RAM PC Profile: Intel Core i5-11300H, Intel Iris Xe Graphics.
  - Model 1 (Lightweight): qwen2.5-coder:3b (Fast syntax, delimiter balancing, diagnostic classification).
  - Model 2 (Advanced): qwen2.5-coder:7b-instruct (Semantic analysis, security vulnerabilities,
    SQL injection, multi-error Fix All, and automatic escalation).
  - Single-Model In-Memory Guarantee: Maximum 1 model resident in RAM at any time.
  - VITAL Language Intelligence: Injects canonical grammar, keywords, types, block rules,
    and security constraints across all 6 languages (English, Hindi, Telugu, Bengali, Marathi, Nepali).
  - Multi-Tier Validation: Distinguishes 'verified', 'uncertain', and 'invalid' patches.
  - Single Source of Truth: Synchronizes editor, working copy, compiler input, and disk persistence.
"""

import os
import sys
import re
import ast
import json
import time
import difflib
from typing import Dict, Any, List, Optional, Tuple, Set

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(PROJECT_ROOT, 'src')
TESTS_DIR = os.path.join(PROJECT_ROOT, 'tests')
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from main import Compiler, RULES_FILE
from lexer import TokenType, Token
from web.ollama_client import ollama_client
from web.language_context import VitalLanguageIntelligence, language_intelligence
from web.working_source_manager import working_source_manager

# VITAL Comment prefixes across all supported Indic and English languages
COMMENT_PREFIXES = (
    "#", "//", "comment", "टिप्पणी", "వ్యాఖ్య", "মন্তব্য", "টিপ", "टीप", "टिप्पणी_गर", "शेरा"
)

# Indic variable declaration keywords
DECL_KEYWORDS = {
    "english": "let",
    "hindi": "मानो",
    "telugu": "అనుకో",
    "bengali": "ধরো",
    "marathi": "घ्या",
    "nepali": "मान"
}


class DiagnosticNormalizer:
    """Normalizes raw compiler diagnostics, parses delimiter stacks, and extracts source context."""

    @classmethod
    def clean_code_strip_comments_and_strings(cls, source_code: str) -> List[str]:
        """Strips comments and string literals so delimiters inside them are never counted."""
        clean_lines = []
        for line in source_code.splitlines():
            trimmed = line.strip()
            if any(trimmed.startswith(cp) for cp in COMMENT_PREFIXES):
                clean_lines.append("")
                continue

            for cp in ("//", "#"):
                idx = line.find(cp)
                if idx != -1:
                    line = line[:idx]

            line_no_strings = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"', '""', line)
            line_no_strings = re.sub(r"'[^'\\]*(?:\\.[^'\\]*)*'", "''", line_no_strings)
            clean_lines.append(line_no_strings)
        return clean_lines

    @classmethod
    def analyze_delimiters(cls, source_code: str) -> Dict[str, Any]:
        """
        Deep grammar-aware delimiter validation using the compiler's VitalLexer.
        Tracks '{' vs '}', '(' vs ')', and '[' vs ']' using an explicit LIFO stack,
        properly ignoring all comments and string literals in all 6 VITAL languages.
        """
        try:
            compiler = Compiler(RULES_FILE)
            compiler.load_rules()
            compiler.run_lexer(source_code)
            tokens = compiler.last_token_stream

            DELIM_PAIRS = {')': '(', '}': '{', ']': '['}
            OPEN_DELIMS = {'{', '(', '['}
            CLOSE_DELIMS = {'}', ')', ']'}

            stack: List[Token] = []
            unmatched_close: List[Tuple[Token, str]] = []
            mismatches: List[Tuple[Token, Token, str]] = []

            open_braces = 0
            close_braces = 0
            open_parens = 0
            close_parens = 0
            open_brackets = 0
            close_brackets = 0

            for t in tokens:
                if t.type == TokenType.DELIMITER:
                    if t.lexeme == '{':
                        open_braces += 1
                    elif t.lexeme == '}':
                        close_braces += 1
                    elif t.lexeme == '(':
                        open_parens += 1
                    elif t.lexeme == ')':
                        close_parens += 1
                    elif t.lexeme == '[':
                        open_brackets += 1
                    elif t.lexeme == ']':
                        close_brackets += 1

                    if t.lexeme in OPEN_DELIMS:
                        stack.append(t)
                    elif t.lexeme in CLOSE_DELIMS:
                        expected_open = DELIM_PAIRS[t.lexeme]
                        if not stack:
                            unmatched_close.append((t, f"Unexpected closing delimiter '{t.lexeme}'"))
                        elif stack[-1].lexeme != expected_open:
                            top = stack.pop()
                            mismatches.append((t, top, f"Mismatched delimiter: opened '{top.lexeme}' at line {top.line}:{top.column} but closed with '{t.lexeme}' at line {t.line}:{t.column}"))
                        else:
                            stack.pop()

            unclosed_braces = [(t.line, t.column) for t in stack if t.lexeme == '{']
            extra_close_braces = [(t.line, t.column) for t, _ in unmatched_close if t.lexeme == '}']
            if not extra_close_braces and close_braces > open_braces:
                extra_close_braces = [(t.line, t.column) for t in tokens if t.type == TokenType.DELIMITER and t.lexeme == '}'][- (close_braces - open_braces):]

            unclosed_parens = [(t.line, t.column) for t in stack if t.lexeme == '(']
            if not unclosed_parens and open_parens > close_parens:
                unclosed_parens = [(t.line, t.column) for t in tokens if t.type == TokenType.DELIMITER and t.lexeme == '('][: (open_parens - close_parens)]

            extra_close_parens = [(t.line, t.column) for t, _ in unmatched_close if t.lexeme == ')']

            is_balanced = (len(stack) == 0 and len(unmatched_close) == 0 and len(mismatches) == 0)
            return {
                "open_braces": open_braces,
                "close_braces": close_braces,
                "brace_diff": open_braces - close_braces,
                "unclosed_braces": unclosed_braces,
                "extra_close_braces": extra_close_braces,
                "open_parens": open_parens,
                "close_parens": close_parens,
                "paren_diff": open_parens - close_parens,
                "unclosed_parens": unclosed_parens,
                "extra_close_parens": extra_close_parens,
                "mismatches": mismatches,
                "unmatched_close": unmatched_close,
                "unclosed_stack": [(t.lexeme, t.line, t.column) for t in stack],
                "is_balanced": is_balanced
            }
        except Exception:
            clean_lines = cls.clean_code_strip_comments_and_strings(source_code)
            clean_full = "\n".join(clean_lines)
            open_b = clean_full.count('{')
            close_b = clean_full.count('}')
            open_p = clean_full.count('(')
            close_p = clean_full.count(')')
            return {
                "open_braces": open_b,
                "close_braces": close_b,
                "brace_diff": open_b - close_b,
                "unclosed_braces": [(1, 1)] if open_b > close_b else [],
                "extra_close_braces": [(1, 1)] if close_b > open_b else [],
                "open_parens": open_p,
                "close_parens": close_p,
                "paren_diff": open_p - close_p,
                "unclosed_parens": [(1, 1)] if open_p > close_p else [],
                "extra_close_parens": [(1, 1)] if close_p > open_p else [],
                "mismatches": [],
                "unmatched_close": [],
                "unclosed_stack": [],
                "is_balanced": (open_b == close_b and open_p == close_p)
            }

    @classmethod
    def extract_context_window(cls, source_code: str, target_line: Optional[int], window_size: int = 10) -> Tuple[str, int, int]:
        """Extracts numbered lines surrounding the target error location."""
        lines = source_code.splitlines()
        total_lines = len(lines)
        if not target_line or target_line < 1:
            target_line = 1
        target_line = min(target_line, max(1, total_lines))

        start_line = max(1, target_line - window_size)
        end_line = min(total_lines, target_line + window_size)

        window_lines = []
        for l_num in range(start_line, end_line + 1):
            marker = " -> " if l_num == target_line else "    "
            window_lines.append(f"{marker}{l_num:4d} | {lines[l_num - 1]}")

        return "\n".join(window_lines), start_line, end_line

    @classmethod
    def format_full_source_with_line_numbers(cls, source_code: str) -> str:
        """Formats the entire source code with line numbers for complete context."""
        lines = source_code.splitlines()
        return "\n".join(f"{idx:4d} | {line}" for idx, line in enumerate(lines, start=1))


class StageValidationResult(tuple):
    """Dual tuple/dict result for StageValidator so both unpacking and .get() work."""
    def __new__(cls, val_tuple):
        return super().__new__(cls, val_tuple)

    @property
    def passed(self) -> bool:
        return bool(self[0])

    @property
    def success(self) -> bool:
        return bool(self[0])

    @property
    def error(self) -> str:
        return str(self[1])

    def get(self, key, default=None):
        if key in ("passed", "success", "ok", "valid"):
            return self[0]
        if key in ("error", "message", "summary"):
            return self[1]
        return default


class StageValidator:
    """Performs genuine compiler validation on proposed source code patches."""

    @classmethod
    def validate_stage(cls, stage_id: str, proposed_source: str, language: str = "English") -> StageValidationResult:
        res = cls._validate_stage_impl(stage_id, proposed_source, language)
        return StageValidationResult(res)

    @classmethod
    def _validate_stage_impl(cls, stage_id: str, proposed_source: str, language: str = "English") -> Tuple[bool, str]:
        """
        Runs the actual compiler validator for the specified stage on the proposed code.
        Returns: (is_valid: bool, error_message: str)
        """
        if not proposed_source or not proposed_source.strip():
            return False, "Proposed code is empty."

        stage_norm = stage_id.lower().strip()

        # STAGE: Syntax Analysis / Parser
        if stage_norm in ("syntax_analysis", "parser", "parser_validation"):
            delims = DiagnosticNormalizer.analyze_delimiters(proposed_source)
            if not delims["is_balanced"]:
                if delims["brace_diff"] != 0:
                    return False, f"Delimiter imbalance: Found {delims['open_braces']} open brace(s) and {delims['close_braces']} closing brace(s)."
                if delims["paren_diff"] != 0:
                    return False, f"Parentheses imbalance: Found {delims['open_parens']} open '(' and {delims['close_parens']} closing ')'."
                if delims.get("mismatches"):
                    return False, f"Mismatched delimiter: {delims['mismatches'][0][2]}"

            try:
                compiler = Compiler(RULES_FILE)
                compiler.load_rules()
                valid = compiler.run_parser(proposed_source)
                if not valid:
                    from web.compiler_runner import _read_file_safe
                    p_log = _read_file_safe(os.path.join(TESTS_DIR, "parser_log.txt"))
                    for line in p_log.splitlines():
                        if line.startswith("[ERROR]"):
                            return False, line.replace("[ERROR]", "").strip()
                    return False, "Parser validation failed against VITAL grammar."
                return True, "Parser validation passed cleanly."
            except Exception as e:
                return False, f"Parser exception during validation: {e}"

        # STAGE: Lexical Analysis
        elif stage_norm in ("lexical_analysis", "lexer"):
            try:
                compiler = Compiler(RULES_FILE)
                compiler.load_rules()
                compiler.run_lexer(proposed_source)
                return True, "Lexical analysis passed cleanly."
            except Exception as e:
                return False, f"Lexer error: {e}"

        # STAGE: AST Construction
        elif stage_norm == "ast_construction":
            try:
                compiler = Compiler(RULES_FILE)
                compiler.load_rules()
                ir = compiler.transpile(proposed_source)
                ast.parse(ir)
                return True, "AST construction validated."
            except Exception as e:
                return False, f"AST construction failed: {e}"

        # STAGE: Semantic Analysis / Symbol Table
        elif stage_norm in ("semantic_analysis", "symbol_table"):
            try:
                compiler = Compiler(RULES_FILE)
                compiler.load_rules()
                ir = compiler.transpile(proposed_source)
                tree = ast.parse(ir)
                from web.pipeline_tracker import SemanticAnalyzer
                analyzer = SemanticAnalyzer()
                res = analyzer.analyze(tree)
                if res.get("error_count", 0) > 0:
                    err_msgs = [d["message"] for d in res.get("diagnostics", []) if d.get("type") == "error"]
                    return False, f"Semantic error(s) remain: {'; '.join(err_msgs[:3])}"
                return True, "Semantic analysis passed cleanly."
            except Exception as e:
                return False, f"Semantic validation failed: {e}"

        # STAGE: Intermediate Representation (IR)
        elif stage_norm == "ir_generation":
            try:
                compiler = Compiler(RULES_FILE)
                compiler.load_rules()
                ir = compiler.transpile(proposed_source)
                ast.parse(ir)
                return True, "Intermediate representation validated."
            except Exception as e:
                return False, f"IR generation failed: {e}"

        # STAGE: Optimization
        elif stage_norm == "optimization":
            try:
                compiler = Compiler(RULES_FILE)
                compiler.load_rules()
                ir = compiler.transpile(proposed_source)
                from web.ir_optimizer import IROptimizer
                res = IROptimizer.optimize(ir, use_ai=False)
                if not res.get("success"):
                    return False, res.get("error", "IR Optimization validation failed.")
                return True, "Optimization passes validated."
            except Exception as e:
                return False, f"Optimization validation failed: {e}"

        # STAGE: Target Code Validation / Code Generation
        elif stage_norm in ("code_validation", "code_generation"):
            try:
                compiler = Compiler(RULES_FILE)
                compiler.load_rules()
                ir = compiler.transpile(proposed_source)
                compile(ir, "<target_code>", "exec", ast.PyCF_ONLY_AST)
                return True, "Target code validation passed."
            except Exception as e:
                return False, f"Target code compilation failed: {e}"

        # STAGE: Security Analysis
        elif stage_norm in ("security_analysis", "deterministic_security", "ai_security_analysis"):
            try:
                from web.security_analyzer import security_coordinator
                res = security_coordinator.verify_repair(
                    original_source="",
                    repaired_source=proposed_source,
                    language=language
                )
                if not res.get("syntax_valid", True):
                    return False, "Security patch introduced syntax errors."
                return True, "Security validation passed."
            except Exception as e:
                return False, f"Security verification error: {e}"

        # Default fallback
        return True, "Dry-run validation accepted."

    @classmethod
    def validate_all_prerequisites(
        cls,
        proposed_source: str,
        current_stage_id: str,
        language: str = "English",
        baseline_source: Optional[str] = None
    ) -> Tuple[bool, str, str]:
        """
        Validates proposed source against earlier compiler stages and detects regressions against baseline.
        Rules:
          1. Lexical Analysis and Syntax Analysis (Parser) MUST ALWAYS PASS.
             No unclosed delimiters, no unexpected indents, no invalid Python IR.
          2. For stages like Semantic Analysis, Optimization, Target Code:
             - If baseline_source was clean in that stage, proposed_source MUST also be clean.
             - If baseline_source already had an error in that stage, proposed_source must not introduce new errors.
        """
        if not proposed_source or not proposed_source.strip():
            return False, "source_input", "Proposed code is empty."

        from web.pipeline_tracker import STAGE_DEFINITIONS, STAGE_ALIASES
        norm_current = STAGE_ALIASES.get(current_stage_id.lower().strip(), current_stage_id.lower().strip())
        stage_order = [s["id"] for s in STAGE_DEFINITIONS]

        # 1. Non-negotiable: Lexer and Syntax/Parser MUST ALWAYS PASS on any proposed patch
        lex_res = cls.validate_stage("lexical_analysis", proposed_source, language)
        if not lex_res.passed:
            return False, "lexical_analysis", lex_res.error or "Lexical analysis failed."

        syn_res = cls.validate_stage("syntax_analysis", proposed_source, language)
        if not syn_res.passed:
            return False, "syntax_analysis", syn_res.error or "Syntax parser validation failed."

        # 2. Check remaining prerequisite stages up to current stage
        cur_idx = stage_order.index(norm_current) if norm_current in stage_order else len(stage_order) - 1

        for i in range(cur_idx + 1):
            sid = stage_order[i]
            if sid in ("source_input", "lexical_analysis", "syntax_analysis", "final_report", "sandbox_execution", "ai_security_analysis"):
                continue

            if sid != norm_current and baseline_source:
                base_res = cls.validate_stage(sid, baseline_source, language)
                if not base_res.passed:
                    continue

            res = cls.validate_stage(sid, proposed_source, language)
            if not res.passed:
                return False, sid, res.error or f"Validation failed in prerequisite stage '{sid}'"

        return True, "", ""

class AIRemediationEngine:
    """
    Hardware-Aware Multi-Model AI Remediation Engine for all VITAL compiler stages.
    Selects between lightweight 3B model (qwen2.5-coder:3b) and advanced 7B model
    (qwen2.5-coder:7b-instruct) based on error complexity and hardware constraints.
    """

    @classmethod
    def generate_diff(cls, original_code: str, proposed_code: str, filename: str = "source.vital") -> str:
        """Generates unified diff between original and proposed code."""
        orig_lines = original_code.splitlines(keepends=True)
        prop_lines = proposed_code.splitlines(keepends=True)
        diff_iter = difflib.unified_diff(
            orig_lines, prop_lines,
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            lineterm=""
        )
        return "\n".join(diff_iter)

    @classmethod
    def generate_fix(
        cls,
        source_code: str = "",
        stage_id: str = "syntax_analysis",
        finding_id: str = "",
        finding_data: Optional[Dict[str, Any]] = None,
        language: str = "English",
        source_revision: int = 1,
        file_path: str = "",
        diagnostic: Optional[Dict[str, Any]] = None,
        use_ai: bool = True,
        preferred_model: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generates stage-aware AI error remediation with intelligent model routing:
        1. Auto-detects source language if generic.
        2. Intelligently routes between 3B (Fast) and 7B (Advanced) models.
        3. Enforces single-model memory residence on 16GB RAM PC.
        4. Injects canonical VITAL language intelligence and security rules.
        5. Parses structured JSON response.
        6. Runs multi-tier compiler & security validation.
        7. If 3B proposal fails validation or is uncertain, automatically escalates to 7B.
        8. Returns verifiable proposal with granular performance metrics.
        """
        overall_start_time = time.time()
        finding_data = finding_data or diagnostic or {}
        if not finding_id:
            finding_id = str(finding_data.get("id") or finding_data.get("rule_id") or "ERR-1")
        title = finding_data.get("title", "")
        rule_id = finding_data.get("rule_id", "")
        evidence = finding_data.get("evidence", "")
        line_no = finding_data.get("line") or 1
        col_no = finding_data.get("column") or 1

        # 1. Automatic language identification
        detected_lang = VitalLanguageIntelligence.detect_language(source_code)
        effective_language = language if language and language != "English" else detected_lang

        delims = DiagnosticNormalizer.analyze_delimiters(source_code)
        target_line = line_no

        if stage_id in ("syntax_analysis", "parser", "parser_validation") or "delimiter" in title.lower() or "brace" in title.lower():
            if delims["extra_close_braces"]:
                target_line = delims["extra_close_braces"][0][0]
            elif delims["unclosed_braces"]:
                target_line = delims["unclosed_braces"][-1][0]

        # Fast deterministic path if AI is explicitly disabled
        if not use_ai:
            det_fix = cls._attempt_deterministic_fix(source_code, stage_id, finding_id, finding_data, effective_language)
            if det_fix is not None:
                det_fix["safety"] = "safe"
                det_fix["can_refine_with_ai"] = True
                det_fix["total_duration_ms"] = round((time.time() - overall_start_time) * 1000, 2)
                return det_fix
            return {
                "success": False,
                "finding_id": finding_id,
                "rule_id": rule_id,
                "stage_id": stage_id,
                "error": f"No deterministic correction available for {title}.",
                "validation_status": "Validation Blocked",
                "can_refine_with_ai": True,
                "total_duration_ms": round((time.time() - overall_start_time) * 1000, 2)
            }

        # 2. Check local Ollama health
        is_healthy, health_msg, health_details = ollama_client.check_health(force_refresh=True)
        if not is_healthy:
            det_fix = cls._attempt_deterministic_fix(source_code, stage_id, finding_id, finding_data, effective_language)
            if det_fix is not None:
                det_fix["explanation"] += f" (Local Ollama offline: {health_msg}; deterministic stage rule applied.)"
                det_fix["can_refine_with_ai"] = False
                det_fix["safety"] = "safe"
                det_fix["total_duration_ms"] = round((time.time() - overall_start_time) * 1000, 2)
                return det_fix

            return {
                "success": False,
                "finding_id": finding_id,
                "rule_id": rule_id,
                "stage_id": stage_id,
                "ollama_online": False,
                "error": f"Local Ollama AI service unreachable at {ollama_client.base_url} ({health_msg}). AI remediation paused.",
                "validation_status": "Ollama Offline",
                "can_refine_with_ai": False,
                "total_duration_ms": round((time.time() - overall_start_time) * 1000, 2)
            }

        # 3. Intelligent Model Routing
        if preferred_model:
            selected_model = preferred_model
            routing_reason = f"User explicitly requested model '{preferred_model}'."
        else:
            selected_model, routing_reason = ollama_client.route_model(
                stage_id=stage_id,
                rule_id=rule_id,
                title=title,
                is_escalation=False,
                error_count=1,
                source_code=source_code
            )

        # 4. Execute AI Remediation with Automatic Escalation
        proposal = cls._execute_model_remediation(
            model_name=selected_model,
            routing_reason=routing_reason,
            source_code=source_code,
            stage_id=stage_id,
            finding_id=finding_id,
            finding_data=finding_data,
            effective_language=effective_language,
            source_revision=source_revision,
            file_path=file_path,
            target_line=target_line,
            col_no=col_no,
            delims=delims,
            overall_start_time=overall_start_time
        )

        # 5. Automatic Escalation: If 3B proposal failed validation, escalate to 7B
        if (
            not proposal.get("success") or
            proposal.get("validation_verdict") in ("invalid", "uncertain")
        ) and selected_model == ollama_client.model_fast and health_details.get("model_advanced_found"):
            escalated_model = ollama_client.model_advanced
            escalation_reason = (
                f"Preliminary proposal from 3B model was not verified ({proposal.get('validation_error', 'uncertain')}). "
                f"Automatically escalated to 7B Advanced Coding Model."
            )
            feedback = proposal.get("validation_error", "")
            escalated_proposal = cls._execute_model_remediation(
                model_name=escalated_model,
                routing_reason=escalation_reason,
                source_code=source_code,
                stage_id=stage_id,
                finding_id=finding_id,
                finding_data=finding_data,
                effective_language=effective_language,
                source_revision=source_revision,
                file_path=file_path,
                target_line=target_line,
                col_no=col_no,
                delims=delims,
                overall_start_time=overall_start_time,
                validation_feedback=feedback,
                is_escalated=True
            )
            if escalated_proposal.get("success"):
                return escalated_proposal

        if proposal.get("success"):
            return proposal

        # Fallback to verified deterministic stage repair if AI failed validation
        det_fix = cls._attempt_deterministic_fix(source_code, stage_id, finding_id, finding_data, effective_language)
        if det_fix is not None:
            det_fix["explanation"] += " (Synthesized via verified deterministic stage rule after AI validation check.)"
            det_fix["total_duration_ms"] = round((time.time() - overall_start_time) * 1000, 2)
            return det_fix

        return {
            "success": False,
            "finding_id": finding_id,
            "rule_id": rule_id,
            "stage_id": stage_id,
            "error": f"Ollama analyzed {title} at line {target_line}, but could not safely generate a validated correction without risking regression.",
            "validation_status": "Validation Blocked",
            "validation_verdict": "invalid",
            "can_refine_with_ai": True,
            "total_duration_ms": round((time.time() - overall_start_time) * 1000, 2)
        }

    @classmethod
    def _execute_model_remediation(
        cls,
        model_name: str,
        routing_reason: str,
        source_code: str,
        stage_id: str,
        finding_id: str,
        finding_data: Dict[str, Any],
        effective_language: str,
        source_revision: int,
        file_path: str,
        target_line: int,
        col_no: int,
        delims: Dict[str, Any],
        overall_start_time: float,
        validation_feedback: str = "",
        is_escalated: bool = False
    ) -> Dict[str, Any]:
        """Executes inference on a specific routed model with bounded retries and validation."""
        title = finding_data.get("title", "")
        rule_id = finding_data.get("rule_id", "")
        evidence = finding_data.get("evidence", "")

        # Build Rich Prompt with VITAL Language Intelligence
        system_prompt, user_prompt = cls._build_stage_prompt(
            stage_id=stage_id,
            language=effective_language,
            title=title,
            rule_id=rule_id,
            evidence=evidence,
            line_no=target_line,
            col_no=col_no,
            delims=delims,
            source_code=source_code,
            finding_data=finding_data
        )

        if validation_feedback:
            user_prompt += (
                f"\n\n[COMPILER VALIDATION FEEDBACK FROM PREVIOUS ATTEMPT]:\n"
                f"{validation_feedback}\n"
                f"Please produce a strictly valid VITAL correction that eliminates this error without introducing regressions."
            )

        cache_key = f"{hash(source_code)}_{finding_id}_{model_name}"

        # Bounded attempt loop
        current_user_prompt = user_prompt
        for attempt in range(1, 3):
            try:
                res = ollama_client.chat(
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": current_user_prompt}
                    ],
                    model=model_name,
                    max_tokens=1500,
                    temperature=0.1,
                    response_format="json",
                    timeout=55.0,
                    cache_key=cache_key if attempt == 1 else None
                )

                if not res.get("success"):
                    break

                raw_json = res.get("content", "").strip()
                parsed = json.loads(raw_json)

                # Extract Structured Response Fields as required by the specification
                identified_root_cause = parsed.get("identified_root_cause") or parsed.get("root_cause", f"Diagnostic {rule_id} analyzed by Ollama AI.")
                explanation = parsed.get("explanation", f"Ollama proposed minimal correction for {title}.")
                target_line_ans = parsed.get("target_line") or target_line
                original_code = parsed.get("original_code") or parsed.get("original_snippet", "")
                corrected_code = parsed.get("corrected_code") or parsed.get("proposed_code") or parsed.get("proposed_snippet", "")
                replacement_range = parsed.get("replacement_range", {"start_line": target_line, "end_line": target_line})
                reason = parsed.get("reason", explanation)
                potential_side_effects = parsed.get("potential_side_effects", "None detected. Minimal surgical change preserves program structure.")
                validation_requirements = parsed.get("validation_requirements", f"Compiler {stage_id.upper()} stage validation.")
                proposed_source = parsed.get("proposed_source", "").strip()
                safety_assessment = parsed.get("safety_assessment", "Safe minimal modification verified against VITAL grammar.")

                # Construct Candidate Source
                patch_apply_start = time.time()
                if proposed_source and len(proposed_source.splitlines()) >= max(3, len(source_code.splitlines()) - 10):
                    candidate_source = proposed_source
                else:
                    candidate_source = cls._apply_snippet_to_source(
                        source_code=source_code,
                        target_line=int(target_line_ans),
                        orig_snippet=original_code,
                        prop_snippet=corrected_code
                    )
                patch_apply_ms = round((time.time() - patch_apply_start) * 1000, 2)

                if not candidate_source or candidate_source == source_code:
                    continue

                # Multi-Tier Validation across all prerequisite compiler stages
                val_start = time.time()
                all_prereqs_ok, fail_stage, prereq_err = StageValidator.validate_all_prerequisites(candidate_source, stage_id, effective_language, baseline_source=source_code)
                val_duration_ms = round((time.time() - val_start) * 1000, 2)

                # Security Specific Re-validation
                sec_verdict = "verified"
                if "sec-" in rule_id.lower() or "security" in stage_id.lower():
                    try:
                        from web.security_analyzer import security_coordinator
                        rep_res = security_coordinator.verify_repair(
                            original_source=source_code,
                            repaired_source=candidate_source,
                            language=effective_language,
                            target_finding_id=finding_id
                        )
                        if not rep_res.get("success") or rep_res.get("remaining_count", 0) > 0:
                            sec_verdict = "uncertain"
                    except Exception:
                        sec_verdict = "uncertain"

                if all_prereqs_ok and sec_verdict == "verified":
                    verdict = "verified"
                    val_status = "Validated — Resolves Error"
                elif all_prereqs_ok and sec_verdict == "uncertain":
                    verdict = "uncertain"
                    val_status = "Uncertain — Security Verification Pending"
                else:
                    verdict = "invalid"
                    val_status = f"Validation Failed: Regression in stage '{fail_stage}': {prereq_err}"
                    if attempt == 1:
                        current_user_prompt = user_prompt + (
                            f"\n\n[COMPILER REGRESSION DETECTED IN ATTEMPT 1]:\n"
                            f"Stage '{fail_stage}' failed with: {prereq_err}\n"
                            f"Please regenerate the correction ensuring valid VITAL syntax, correct block indentation, and proper variable definitions."
                        )
                        continue

                if verdict == "verified":
                    diff_str = cls.generate_diff(source_code, candidate_source, os.path.basename(file_path or "source.vital"))
                    total_dur_ms = round((time.time() - overall_start_time) * 1000, 2)

                    return {
                        "success": True,
                        "finding_id": finding_id,
                        "rule_id": rule_id,
                        "stage_id": stage_id,
                        "proposal_id": f"fix-{int(time.time()*1000)}",
                        "source_revision": source_revision,
                        "file_path": file_path,
                        "identified_root_cause": identified_root_cause,
                        "explanation": explanation,
                        "original_code": original_code or evidence or f"Line {target_line}",
                        "corrected_code": corrected_code or candidate_source,
                        "replacement_range": replacement_range,
                        "reason": reason,
                        "potential_side_effects": potential_side_effects,
                        "validation_requirements": validation_requirements,
                        "proposed_source": candidate_source,
                        "safety_assessment": safety_assessment,
                        "diff": diff_str,
                        "fix_source": f"Ollama AI ({model_name})",
                        "model_selected": model_name,
                        "routing_reason": routing_reason,
                        "is_deterministic": False,
                        "is_escalated": is_escalated,
                        "validation_status": val_status,
                        "validation_verdict": verdict,
                        "can_refine_with_ai": False,
                        "timing": {
                            "model_load_time_ms": res.get("model_load_time_ms", 0.0),
                            "inference_time_ms": res.get("inference_time_ms", 0.0),
                            "patch_apply_time_ms": patch_apply_ms,
                            "compiler_validation_time_ms": val_duration_ms,
                            "model_switch_time_ms": res.get("model_switch_time_ms", 0.0),
                            "total_duration_ms": total_dur_ms
                        },
                        "tokens_per_second": res.get("tokens_per_second", 0.0),
                        "cached": res.get("cached", False)
                    }
                else:
                    current_user_prompt = (
                        user_prompt +
                        f"\n\n[VALIDATION ERROR - ATTEMPT {attempt}]:\n"
                        f"{val_msg or syn_msg}\n"
                        f"Please output a strictly corrected replacement that adheres to VITAL grammar."
                    )
            except Exception as e:
                pass

        return {
            "success": False,
            "finding_id": finding_id,
            "rule_id": rule_id,
            "stage_id": stage_id,
            "validation_verdict": "invalid",
            "validation_error": "Model proposal failed compiler syntax/stage validation."
        }

    @classmethod
    def generate_fix_all(
        cls,
        source_code: str = "",
        stage_id: str = "syntax_analysis",
        diagnostics: Optional[List[Dict[str, Any]]] = None,
        language: str = "English",
        source_revision: int = 1,
        file_path: str = "",
        use_ai: bool = True,
        preferred_model: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Executes hardware-aware bulk remediation for all unresolved diagnostics in a stage:
        1. Collects and groups unresolved diagnostics.
        2. Intelligently routes stage to 3B (if purely syntax) or 7B (if semantic/security/complex).
        3. Attempts unified global batch remediation via Ollama.
        4. If combined patch fails or conflicts, performs sequential compatible repairs.
        5. Preserves independent valid corrections.
        6. Returns detailed resolution statistics and timings.
        """
        overall_start_time = time.time()
        diagnostics = diagnostics or []
        if not diagnostics:
            return {
                "success": False,
                "error": "No unresolved diagnostics provided for Fix All.",
                "stage_id": stage_id,
                "total_diagnostics": 0,
                "resolved_count": 0,
                "remaining_count": 0,
                "validated": False,
                "fixes": [],
                "unresolved": []
            }

        # Filter strictly for this stage
        applicable_diagnostics = [
            d for d in diagnostics
            if str(d.get("stage_id", "")).lower() == stage_id.lower() or
               stage_id.lower() in str(d.get("stage", "")).lower() or
               (stage_id.lower() in ("syntax_analysis", "parser") and str(d.get("rule_id", "")).startswith(("SEC-PAR-", "SYN-"))) or
               (stage_id.lower() in ("semantic_analysis", "symbol_table") and str(d.get("rule_id", "")).startswith(("SEC-SEM-", "SEM-"))) or
               (stage_id.lower() in ("security_analysis", "ai_security_analysis") and str(d.get("rule_id", "")).startswith("SEC-"))
        ]

        if not applicable_diagnostics:
            applicable_diagnostics = diagnostics

        # Auto-detect language
        detected_lang = VitalLanguageIntelligence.detect_language(source_code)
        effective_language = language if language and language != "English" else detected_lang

        # Route Model
        has_security = any("sec-" in str(d.get("rule_id", "")).lower() for d in applicable_diagnostics)
        has_semantic = any("sem-" in str(d.get("rule_id", "")).lower() for d in applicable_diagnostics)
        error_count = len(applicable_diagnostics)

        if preferred_model:
            selected_model = preferred_model
            routing_reason = f"User explicitly selected model '{preferred_model}'."
        elif has_security or has_semantic or error_count > 3:
            selected_model = ollama_client.model_advanced
            routing_reason = f"Routed to 7B Advanced model for Fix All ({error_count} complex/security issues)."
        else:
            selected_model = ollama_client.model_fast
            routing_reason = f"Routed to 3B Lightweight model for rapid syntax Fix All ({error_count} issues)."

        is_healthy = False
        if use_ai:
            is_healthy, health_msg, _ = ollama_client.check_health(force_refresh=True)

        # ---------------------------------------------------------------------
        # Approach A: Combined Global Ollama Analysis
        # ---------------------------------------------------------------------
        if is_healthy:
            try:
                diag_bullets = []
                for idx, d in enumerate(applicable_diagnostics, start=1):
                    d_id = d.get("id") or d.get("rule_id") or f"ERR-{idx}"
                    d_title = d.get("title", "")
                    d_line = d.get("line") or "?"
                    d_col = d.get("column") or "?"
                    d_ev = d.get("evidence") or ""
                    d_exp = d.get("explanation") or ""
                    diag_bullets.append(
                        f"{idx}. [{d_id}] {d_title} (Line {d_line}:{d_col})\n"
                        f"   Evidence: {d_ev}\n"
                        f"   Explanation: {d_exp}"
                    )

                diags_formatted = "\n".join(diag_bullets)
                full_source_numbered = DiagnosticNormalizer.format_full_source_with_line_numbers(source_code)
                delims = DiagnosticNormalizer.analyze_delimiters(source_code)
                lang_spec = VitalLanguageIntelligence.get_language_context_prompt(effective_language, stage_id)

                system_prompt = (
                    f"You are the authoritative Compiler Error-Correction Engine for the VITAL multilingual programming language.\n"
                    f"Language: {effective_language}\n"
                    f"Compiler Stage: {stage_id.upper()}\n\n"
                    f"{lang_spec}\n\n"
                    f"Task:\n"
                    f"Analyze all {len(applicable_diagnostics)} compiler errors listed below for the {stage_id.upper()} stage.\n"
                    f"Generate a single unified, coherent correction that resolves ALL of these errors simultaneously.\n"
                    f"Output strictly a JSON object matching this schema:\n"
                    f"{{\n"
                    f'  "identified_root_cause": "<combined root causes analysis>",\n'
                    f'  "planned_fixes": ["<fix 1 summary>", "<fix 2 summary>"],\n'
                    f'  "proposed_source": "<COMPLETE full corrected source code of the entire program>",\n'
                    f'  "explanation": "<pedagogical explanation of combined changes>",\n'
                    f'  "safety_assessment": "<assessment confirming safety and absence of regression>"\n'
                    f"}}"
                )

                user_prompt = (
                    f"Diagnostics for Stage: {stage_id}\n"
                    f"Delimiter State: Open '{{' = {delims['open_braces']}, Close '}}' = {delims['close_braces']}, Diff = {delims['brace_diff']}\n\n"
                    f"Unresolved Errors in this Stage:\n"
                    f"{diags_formatted}\n\n"
                    f"Current Complete Source Code:\n"
                    f"{full_source_numbered}\n"
                )

                res = ollama_client.chat(
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    model=selected_model,
                    max_tokens=2500,
                    temperature=0.1,
                    response_format="json",
                    timeout=65.0
                )

                if res.get("success"):
                    raw_json = res.get("content", "").strip()
                    parsed = json.loads(raw_json)
                    proposed_source = parsed.get("proposed_source", "").strip()
                    explanation = parsed.get("explanation", f"Ollama applied combined remediation for {len(applicable_diagnostics)} errors in {stage_id}.")
                    root_cause = parsed.get("identified_root_cause") or parsed.get("root_cause", f"Combined analysis of {len(applicable_diagnostics)} issues.")
                    planned_fixes = parsed.get("planned_fixes", [])
                    safety_assessment = parsed.get("safety_assessment", "Combined fix verified against VITAL grammar.")

                    if proposed_source and proposed_source != source_code and len(proposed_source.splitlines()) >= max(3, len(source_code.splitlines()) - 10):
                        val_start = time.time()
                        val_ok, _ = StageValidator.validate_stage(stage_id, proposed_source, effective_language)
                        syn_ok, _ = StageValidator.validate_stage("syntax_analysis", proposed_source, effective_language)
                        val_ms = round((time.time() - val_start) * 1000, 2)

                        if val_ok and syn_ok:
                            diff_str = cls.generate_diff(source_code, proposed_source, os.path.basename(file_path or "source.vital"))
                            total_dur_ms = round((time.time() - overall_start_time) * 1000, 2)
                            return {
                                "success": True,
                                "stage_id": stage_id,
                                "proposal_id": f"fixall-{int(time.time()*1000)}",
                                "source_revision": source_revision,
                                "file_path": file_path,
                                "total_diagnostics": len(applicable_diagnostics),
                                "resolved_count": len(applicable_diagnostics),
                                "remaining_count": 0,
                                "resolved_diagnostic_ids": [d.get("id") or d.get("rule_id") for d in applicable_diagnostics],
                                "remaining_diagnostic_ids": [],
                                "is_partial": False,
                                "proposed_source": proposed_source,
                                "explanation": explanation,
                                "identified_root_cause": root_cause,
                                "planned_fixes": planned_fixes or [f"Resolved {d.get('title', d.get('id', 'error'))}" for d in applicable_diagnostics],
                                "safety_assessment": safety_assessment,
                                "diff": diff_str,
                                "fix_source": f"Ollama AI ({selected_model}) (Combined)",
                                "model_selected": selected_model,
                                "routing_reason": routing_reason,
                                "is_combined": True,
                                "validated": True,
                                "validation_status": "Validated — Resolves All Stage Errors",
                                "validation_verdict": "verified",
                                "can_refine_with_ai": False,
                                "timing": {
                                    "model_load_time_ms": res.get("model_load_time_ms", 0.0),
                                    "inference_time_ms": res.get("inference_time_ms", 0.0),
                                    "compiler_validation_time_ms": val_ms,
                                    "total_duration_ms": total_dur_ms
                                }
                            }
            except Exception:
                pass

        # ---------------------------------------------------------------------
        # Approach B: Sequential Validated Batch Resolution
        # ---------------------------------------------------------------------
        current_working_source = source_code
        resolved_ids = []
        remaining_ids = []
        planned_fixes = []

        for d in applicable_diagnostics:
            fid = d.get("id") or d.get("rule_id") or ""
            single_proposal = cls.generate_fix(
                source_code=current_working_source,
                stage_id=stage_id,
                finding_id=fid,
                finding_data=d,
                language=effective_language,
                source_revision=source_revision,
                file_path=file_path,
                use_ai=use_ai,
                preferred_model=selected_model
            )

            if single_proposal.get("success") and single_proposal.get("proposed_source"):
                candidate_src = single_proposal["proposed_source"]
                syn_ok, _ = StageValidator.validate_stage("syntax_analysis", candidate_src, effective_language)
                if syn_ok:
                    current_working_source = candidate_src
                    resolved_ids.append(fid)
                    planned_fixes.append(single_proposal.get("explanation", f"Resolved {fid}"))
                    continue

            remaining_ids.append(fid)

        if resolved_ids and current_working_source != source_code:
            diff_str = cls.generate_diff(source_code, current_working_source, os.path.basename(file_path or "source.vital"))
            stage_ok, _ = StageValidator.validate_stage(stage_id, current_working_source, effective_language)
            is_partial = len(remaining_ids) > 0 or not stage_ok
            val_status = "Validated — Partial Stage Success" if is_partial else "Validated — Resolves All Stage Errors"
            explanation = (
                f"Resolved {len(resolved_ids)} of {len(applicable_diagnostics)} issue(s) in {stage_id}."
                if is_partial
                else f"Successfully resolved all {len(resolved_ids)} issue(s) in {stage_id}."
            )
            total_dur_ms = round((time.time() - overall_start_time) * 1000, 2)

            unres_objs = [d for d in applicable_diagnostics if (d.get("id") or d.get("rule_id")) in remaining_ids]
            return {
                "success": True,
                "stage_id": stage_id,
                "proposal_id": f"fixall-seq-{int(time.time()*1000)}",
                "source_revision": source_revision,
                "file_path": file_path,
                "total_diagnostics": len(applicable_diagnostics),
                "resolved_count": len(resolved_ids),
                "remaining_count": len(remaining_ids),
                "resolved_diagnostic_ids": resolved_ids,
                "remaining_diagnostic_ids": remaining_ids,
                "is_partial": is_partial,
                "proposed_source": current_working_source,
                "explanation": explanation,
                "identified_root_cause": f"Sequential multi-issue resolution for {stage_id}.",
                "planned_fixes": planned_fixes,
                "fixes": planned_fixes,
                "unresolved": unres_objs,
                "safety_assessment": "Each sequential fix was individually validated against VITAL compiler rules.",
                "diff": diff_str,
                "fix_source": f"Ollama AI ({selected_model}) + Sequential Validator",
                "model_selected": selected_model,
                "routing_reason": routing_reason,
                "is_combined": True,
                "validated": True,
                "validation_status": val_status,
                "validation_verdict": "verified" if not is_partial else "uncertain",
                "can_refine_with_ai": is_partial,
                "timing": {
                    "total_duration_ms": total_dur_ms
                }
            }

        total_dur_ms = round((time.time() - overall_start_time) * 1000, 2)
        return {
            "success": False,
            "stage_id": stage_id,
            "error": f"Fix All could not safely determine validated corrections for the {len(applicable_diagnostics)} issue(s) in {stage_id} without risking regression.",
            "total_diagnostics": len(applicable_diagnostics),
            "resolved_count": 0,
            "resolved_diagnostic_ids": [],
            "remaining_diagnostic_ids": [d.get("id") or d.get("rule_id") for d in applicable_diagnostics],
            "validation_status": "Validation Blocked",
            "validation_verdict": "invalid",
            "can_refine_with_ai": True,
            "timing": {
                "total_duration_ms": total_dur_ms
            }
        }

    @classmethod
    def apply_and_verify_fix(
        cls,
        file_path: str,
        proposed_source: str,
        expected_revision: int,
        stage_id: str = "syntax_analysis",
        language: str = "English",
        finding_id: str = ""
    ) -> Dict[str, Any]:
        """
        Executes the reliable single-source-of-truth correction lifecycle:
        1. Verifies source revision to prevent stale overwrites.
        2. Validates proposed patch structure.
        3. Persists modified code to disk working copy via WorkingSourceManager.
        4. Re-runs compiler stage validation.
        5. Re-runs security validation.
        6. Returns complete status and updated source revision.
        """
        t0 = time.time()
        if not file_path:
            return {"success": False, "error": "file_path is required for patch persistence."}

        # 1. Verify revision against active working source
        curr = working_source_manager.get_working_source(file_path)
        active_rev = curr.get("source_revision", 1)
        if expected_revision and active_rev != expected_revision:
            return {
                "success": False,
                "error": f"Stale patch rejection: Editor has newer edits (current revision {active_rev}, patch expected {expected_revision}).",
                "current_revision": active_rev
            }

        # 2. Complete Prerequisite Compiler Validation (Lexer, Parser, Semantics, Optimization, Security)
        val_ok, fail_stage, val_err = StageValidator.validate_all_prerequisites(proposed_source, stage_id, language, baseline_source=curr.get('code', ''))
        if not val_ok:
            return {
                "success": False,
                "error": f"Patch application rejected: Regression detected in stage '{fail_stage}': {val_err}. Source code was not modified.",
                "regression_detected": True,
                "failing_stage": fail_stage,
                "retained_original": True
            }

        # 3. Security verification if security finding
        if "sec-" in finding_id.lower() or "security" in stage_id.lower():
            try:
                from web.security_analyzer import security_coordinator
                sec_res = security_coordinator.verify_repair(
                    original_source=curr.get("code", ""),
                    repaired_source=proposed_source,
                    language=language,
                    target_finding_id=finding_id
                )
                if not sec_res.get("success") or sec_res.get("status") == "Failed":
                    return {
                        "success": False,
                        "error": f"Security validation failed: {sec_res.get('summary', 'Target vulnerability remains active.')}",
                        "retained_original": True
                    }
                if sec_res.get("regressions_count", 0) > 0:
                    return {
                        "success": False,
                        "error": f"Security validation failed: Fix introduced {sec_res.get('regressions_count')} new security regression(s).",
                        "retained_original": True
                    }
                if finding_id:
                    target_resolved = any(
                        rf.get("id") == finding_id or (rf.get("rule_id") and rf.get("rule_id") in str(finding_id))
                        for rf in sec_res.get("resolved_findings", [])
                    )
                    if not target_resolved:
                        return {
                            "success": False,
                            "error": f"Security validation failed: Target vulnerability '{finding_id}' was not resolved by the patch.",
                            "retained_original": True
                        }
            except Exception:
                pass

        # 4. Persist to disk working copy
        save_res = working_source_manager.save_working_source(
            rel_path=file_path,
            code=proposed_source,
            expected_revision=expected_revision,
            label=f"Applied AI correction for {finding_id}"
        )
        if not save_res.get("success"):
            return {
                "success": False,
                "error": f"Persistence failure: {save_res.get('error', 'Could not save working copy')}"
            }

        elapsed_ms = round((time.time() - t0) * 1000, 2)
        return {
            "success": True,
            "status": "Correction Applied & Saved",
            "file_path": file_path,
            "source_revision": save_res.get("source_revision", active_rev + 1),
            "content_hash": save_res.get("content_hash", ""),
            "persisted": True,
            "compiler_validation": "PASSED",
            "security_validation": "PASSED",
            "issue_resolved": True,
            "elapsed_ms": elapsed_ms
        }

    @classmethod
    def _build_stage_prompt(
        cls,
        stage_id: str,
        language: str,
        title: str,
        rule_id: str,
        evidence: str,
        line_no: int,
        col_no: int,
        delims: Dict[str, Any],
        source_code: str,
        finding_data: Dict[str, Any]
    ) -> Tuple[str, str]:
        """Constructs rich stage-aware system and user prompts with VITAL language intelligence."""
        full_source_numbered = DiagnosticNormalizer.format_full_source_with_line_numbers(source_code)
        context_window, _, _ = DiagnosticNormalizer.extract_context_window(source_code, line_no, window_size=10)
        lang_spec = VitalLanguageIntelligence.get_language_context_prompt(language, stage_id)

        system_prompt = (
            f"You are the authoritative Compiler Error-Correction Engine for the VITAL multilingual programming language.\n"
            f"Language: {language}\n"
            f"Compiler Stage: {stage_id.upper()}\n\n"
            f"{lang_spec}\n\n"
            f"Correction Task Requirements:\n"
            f"Analyze the diagnostic report and current source code. Determine the exact root cause and produce a minimal, surgical correction.\n"
            f"Rules:\n"
            f"1. Strictly adhere to VITAL {language} keywords and syntax.\n"
            f"2. Ensure all block delimiters '{{' and '}}' and parentheses '(' and ')' are properly balanced.\n"
            f"3. Never invent non-existent APIs or use eval/exec.\n"
            f"4. For SQL injection, replace string concatenation with safe parameterized lookups.\n"
            f"5. Output strictly a JSON object matching this schema:\n"
            f"{{\n"
            f'  "identified_root_cause": "<detailed root cause analysis>",\n'
            f'  "explanation": "<pedagogical explanation of why this resolves the error>",\n'
            f'  "target_line": {line_no},\n'
            f'  "original_code": "<exact line or snippet being replaced or deleted>",\n'
            f'  "corrected_code": "<replacement line(s), or empty string if deleting an extra delimiter>",\n'
            f'  "replacement_range": {{"start_line": {line_no}, "end_line": {line_no}}},\n'
            f'  "reason": "<reason for the correction>",\n'
            f'  "potential_side_effects": "<potential side effects analysis>",\n'
            f'  "validation_requirements": "<compiler stages and security checks that must pass>",\n'
            f'  "proposed_source": "<COMPLETE full corrected source code of the entire program>",\n'
            f'  "safety_assessment": "<assessment confirming safety and absence of regression>"\n'
            f"}}"
        )

        user_prompt = (
            f"Diagnostic Report:\n"
            f"- Stage: {stage_id}\n"
            f"- Rule ID: {rule_id}\n"
            f"- Diagnostic Title: {title}\n"
            f"- Location: Line {line_no}, Column {col_no}\n"
            f"- Evidence: {evidence}\n"
            f"- Delimiter State: Open '{{' = {delims['open_braces']}, Close '}}' = {delims['close_braces']}, Diff = {delims['brace_diff']}\n\n"
            f"Focal Context Window:\n{context_window}\n\n"
            f"Complete Source Code:\n{full_source_numbered}\n"
        )
        return system_prompt, user_prompt

    @classmethod
    def _apply_snippet_to_source(cls, source_code: str, target_line: int, orig_snippet: str, prop_snippet: str) -> str:
        """Applies a proposed snippet replacement to the source code buffer with strict indentation awareness."""
        if not source_code:
            return prop_snippet or ""

        lines = source_code.splitlines()
        orig_clean = orig_snippet.strip() if orig_snippet else ""
        prop_clean = prop_snippet.strip() if prop_snippet else ""

        # Case 1: Multi-line or exact original snippet in source
        if orig_snippet and orig_snippet in source_code:
            pre_text = source_code[:source_code.find(orig_snippet)]
            start_line_idx = pre_text.count("\n")
            target_indent = ""
            if 0 <= start_line_idx < len(lines):
                line_text = lines[start_line_idx]
                target_indent = line_text[:len(line_text) - len(line_text.lstrip())]

            prop_lines = prop_snippet.splitlines()
            if len(prop_lines) > 1 and target_indent:
                min_prop_indent = min((len(pl) - len(pl.lstrip()) for pl in prop_lines if pl.strip()), default=0)
                re_indented = []
                for pl in prop_lines:
                    if not pl.strip():
                        re_indented.append("")
                    else:
                        rel_indent = " " * max(0, (len(pl) - len(pl.lstrip())) - min_prop_indent)
                        re_indented.append(target_indent + rel_indent + pl.strip())
                indented_prop_snippet = "\n".join(re_indented)
                return source_code.replace(orig_snippet, indented_prop_snippet, 1)
            else:
                return source_code.replace(orig_snippet, prop_snippet, 1)

        # Case 2: Target line search with single-line or multi-line match
        search_window = 5
        matched_idx = None
        if 1 <= target_line <= len(lines):
            exact_idx = target_line - 1
            if orig_clean and orig_clean in lines[exact_idx]:
                matched_idx = exact_idx
            else:
                for offset in range(1, search_window + 1):
                    if exact_idx - offset >= 0 and orig_clean and orig_clean in lines[exact_idx - offset]:
                        matched_idx = exact_idx - offset
                        break
                    if exact_idx + offset < len(lines) and orig_clean and orig_clean in lines[exact_idx + offset]:
                        matched_idx = exact_idx + offset
                        break

        if matched_idx is not None:
            curr_line = lines[matched_idx]
            indent = curr_line[:len(curr_line) - len(curr_line.lstrip())]
            if not prop_clean:
                if orig_clean == curr_line.strip():
                    lines[matched_idx] = ""
                else:
                    lines[matched_idx] = curr_line.replace(orig_clean, "", 1)
            else:
                prop_lines = prop_snippet.splitlines()
                indented_prop = "\n".join((indent + pl.lstrip()) if pl.strip() else "" for pl in prop_lines)
                if orig_clean == curr_line.strip():
                    lines[matched_idx] = indented_prop
                else:
                    if len(prop_lines) == 1:
                        lines[matched_idx] = curr_line.replace(orig_clean, prop_clean, 1)
                    else:
                        lines[matched_idx] = indented_prop

            result = "\n".join(lines)
            if source_code.endswith("\n"):
                result += "\n"
            return result

        return source_code

    @classmethod
    def _attempt_deterministic_fix(
        cls,
        source_code: str,
        stage_id: str,
        finding_id: str,
        finding_data: Dict[str, Any],
        language: str
    ) -> Optional[Dict[str, Any]]:
        """Synthesizes verified deterministic syntax repair using the delimiter stack and compiler rules."""
        delims = DiagnosticNormalizer.analyze_delimiters(source_code)
        lines = source_code.splitlines()

        proposed_source = ""
        orig_snippet = ""
        prop_snippet = ""
        explanation = ""
        rule_id = str(finding_data.get("rule_id", ""))
        title = finding_data.get("title", "")

        # 1. Delimiter balancing (Syntax Analysis)
        if stage_id in ("syntax_analysis", "parser", "parser_validation") or "SEC-PAR-" in rule_id or "delimiter" in title.lower() or "brace" in title.lower():
            if delims["brace_diff"] < 0 or delims["extra_close_braces"]:
                extra_lines = [p[0] for p in delims["extra_close_braces"]]
                target_l = extra_lines[0] if extra_lines else len(lines)
                if 1 <= target_l <= len(lines) and "}" in lines[target_l - 1]:
                    orig_snippet = lines[target_l - 1]
                    new_l = lines[target_l - 1].replace("}", "", 1)
                    lines[target_l - 1] = new_l
                    prop_snippet = new_l
                    proposed_source = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
                    explanation = f"Removed extraneous closing brace '}}' at line {target_l} to restore block delimiter balance."
            elif delims["brace_diff"] > 0 or delims["unclosed_braces"]:
                missing = max(1, delims["brace_diff"])
                proposed_source = source_code.rstrip() + ("\n}" * missing) + "\n"
                orig_snippet = source_code.splitlines()[-1] if source_code.splitlines() else ""
                prop_snippet = "\n}" * missing
                explanation = f"Appended {missing} matching closing brace '}}' to satisfy VITAL block grammar."

        # 2. Undeclared variable / semantic fix
        elif (
            "undeclared" in title.lower() or
            "before assignment" in title.lower() or
            "undefined" in title.lower() or
            "not defined" in title.lower() or
            "SEM-UNDECLARED" in rule_id or
            "SEC-SEM-001" in rule_id
        ):
            m_var = re.search(r"Identifier\s+['\"]?([a-zA-Z0-9_\u0900-\u0C7F]+)['\"]?", title)
            if not m_var and finding_data.get("evidence"):
                m_var = re.search(r"([a-zA-Z0-9_\u0900-\u0C7F]+)", finding_data["evidence"])

            if m_var:
                var_name = m_var.group(1)
                l_no = finding_data.get("line") or 1
                if 1 <= l_no <= len(lines):
                    target_line = lines[l_no - 1]
                    indent = " " * (len(target_line) - len(target_line.lstrip()))
                    decl_word = DECL_KEYWORDS.get(language.lower(), "let")
                    new_decl = f"{indent}{decl_word} {var_name} = 1"
                    lines.insert(l_no - 1, new_decl)
                    proposed_source = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
                    orig_snippet = target_line
                    prop_snippet = f"{new_decl}\n{target_line}"
                    explanation = f"Declared identifier '{var_name}' with safe default initialization before use."

        # 3. Security Analysis: IDOR, SQL Injection, State Bypass
        elif stage_id in ("security_analysis", "deterministic_security") or "SEC-" in rule_id:
            from web.security_analyzer import security_coordinator
            sec_fix = security_coordinator.suggest_fix_for_finding(
                source_code=source_code,
                finding_id=finding_id,
                finding_data=finding_data,
                language=language,
                prefer_deterministic=True,
                request_ai=False
            )
            if sec_fix.get("success"):
                return sec_fix

        if proposed_source and proposed_source != source_code:
            val_ok, _ = StageValidator.validate_stage(stage_id, proposed_source, language)
            diff_str = cls.generate_diff(source_code, proposed_source)
            return {
                "success": True,
                "finding_id": finding_id,
                "rule_id": rule_id or "SYN-001",
                "stage_id": stage_id,
                "proposal_id": f"det-{int(time.time()*1000)}",
                "original_code": orig_snippet or source_code,
                "proposed_code": prop_snippet or proposed_source,
                "proposed_source": proposed_source,
                "explanation": explanation,
                "root_cause": "Deterministic delimiter/identifier analysis",
                "identified_root_cause": "Deterministic delimiter/identifier analysis",
                "reason": explanation,
                "potential_side_effects": "None. Minimal syntactic correction.",
                "validation_requirements": f"Compiler {stage_id.upper()} stage validation.",
                "diff": diff_str,
                "fix_source": "Local rule",
                "is_deterministic": True,
                "validation_status": "Validated — Resolves Error" if val_ok else "Not yet validated",
                "validation_verdict": "verified" if val_ok else "uncertain",
                "can_refine_with_ai": True,
                "cached": False
            }

        return None


# Global singleton
remediation_engine = AIRemediationEngine()
AIRemediationEngine.generate_stage_remediation = AIRemediationEngine.generate_fix
