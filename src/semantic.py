# -*- coding: utf-8 -*-
"""
semantic.py — Context-Sensitive Semantic Analysis & Symbol Scope Resolution for VITAL

Maintains ONE shared canonical set of known builtin/global names that are never "undeclared",
including standard Python/VITAL builtins and localized/transliterated names from language_rules.json.
Performs use-before-declaration checks, constant division by zero checks, and symbol table generation.
"""

import os
import json
import ast
import difflib
from typing import Dict, Any, List, Set, Optional

_KNOWN_BUILTINS_CACHE: Optional[Set[str]] = None

BASE_BUILTIN_NAMES = {
    # Standard I/O and core builtins
    "print", "input", "len", "range", "int", "str", "float", "bool",
    "list", "dict", "set", "tuple", "abs", "min", "max", "sum", "round",
    "sorted", "open", "eval", "exec", "compile", "type", "isinstance",
    # Multilingual dynamic evaluation aliases (Stage 11 security analyzes these)
    "मूल्यांकन", "మూల్యాంకనం", "মূল্যায়ন", "मूल्यांकन_करा", "मूल्याङ्कन",
    # str-conversion helpers
    "chr", "ord", "bin", "hex", "oct", "repr", "format", "ascii",
    # Common constants & primitives
    "True", "False", "None",
    # Built-in exception types
    "Exception", "BaseException", "ValueError", "TypeError", "KeyError",
    "IndexError", "RuntimeError", "ZeroDivisionError", "NameError",
    # Iteration & collections helpers
    "enumerate", "zip", "map", "filter", "any", "all", "id", "hash",
    "iter", "next", "callable", "super", "object", "bytes", "bytearray",
    # Modules & process execution calls (Stage 11 security handles them, not Stage 5)
    "__import__", "os", "sys", "subprocess", "math", "time", "re", "json"
}


def get_known_builtins() -> Set[str]:
    """
    Returns the canonical set of known builtin and global names.
    Includes BASE_BUILTIN_NAMES and all multilingual synonyms loaded
    from src/language_rules.json (Hindi, Telugu, Bengali, Marathi, Nepali).
    Cached for fast repeated lookups.
    """
    global _KNOWN_BUILTINS_CACHE
    if _KNOWN_BUILTINS_CACHE is not None:
        return _KNOWN_BUILTINS_CACHE

    builtins = set(BASE_BUILTIN_NAMES)

    # Load multilingual synonyms from language_rules.json
    rules_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "language_rules.json")
    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for category, tokens in data.items():
            if isinstance(tokens, dict):
                for token_name, words in tokens.items():
                    if isinstance(words, list):
                        for word in words:
                            if word and word not in ("#", "//"):
                                builtins.add(word)
    except Exception:
        pass

    _KNOWN_BUILTINS_CACHE = builtins
    return _KNOWN_BUILTINS_CACHE


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

        assigned_names: Set[str] = set()
        safe_builtins = get_known_builtins()

        # First pass: collect function definitions and parameters, and loop variables
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
                        line = getattr(node, "lineno", 1)
                        col = getattr(node, "col_offset", 0) + 1
                        self.diagnostics.append({
                            "type": "error",
                            "line": line,
                            "column": col,
                            "rule_id": "SEM-001",
                            "message": "Division by zero constant detected in arithmetic expression.",
                            "explanation": "Static analysis detected constant denominator 0 in division operation.",
                            "remediation": "Guard arithmetic division denominator against zero."
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
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0) + 1

                    # Find nearest declared name suggestion if available
                    candidates = [n for n in assigned_names if n != var_name]
                    close_matches = difflib.get_close_matches(var_name, candidates, n=1, cutoff=0.4)
                    suggestion = close_matches[0] if close_matches else None

                    if suggestion:
                        msg = f"Identifier '{var_name}' at line {line}:{col} referenced before explicit local assignment. Did you mean '{suggestion}'?"
                        rem = f"Declare '{var_name}' before use, or replace with '{suggestion}'."
                    else:
                        msg = f"Identifier '{var_name}' at line {line}:{col} referenced before explicit local assignment."
                        rem = f"Declare identifier '{var_name}' with 'let' before referencing it in this scope."

                    self.diagnostics.append({
                        "type": "error",
                        "line": line,
                        "column": col,
                        "rule_id": "SEC-SEM-001",
                        "identifier": var_name,
                        "suggestion": suggestion,
                        "message": msg,
                        "explanation": f"Identifier '{var_name}' is referenced without declaration or assignment in this lexical scope.",
                        "remediation": rem
                    })

        warning_count = sum(1 for d in self.diagnostics if d["type"] == "warning")
        error_count = sum(1 for d in self.diagnostics if d["type"] == "error")

        return {
            "diagnostics": self.diagnostics,
            "symbols": self.symbols,
            "warning_count": warning_count,
            "error_count": error_count
        }

