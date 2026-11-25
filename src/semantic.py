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

ANALYZER_VERSION = "2.4.0"
_KNOWN_BUILTINS_CACHE: Optional[Set[str]] = None

BASE_BUILTIN_NAMES = {
    # Standard I/O and core builtins
    "print", "input", "len", "range", "int", "str", "float", "bool",
    "list", "dict", "set", "tuple", "abs", "min", "max", "sum", "round",
    "sorted", "open", "eval", "exec", "compile", "type", "isinstance",
    # Multilingual dynamic evaluation aliases (Stage 11 security analyzes these)
    "मूल्यांकन", "మూల్యాంకనం", "মূল্যায়ন", "मूल्यांकन_करा", "मूल्याङ्कन",
    "निष्पादित", "చలాఓ", "అమలు_చేయి", "চালাও", "নিষ্পাদন", "चालवा", "चलाऊ",
    "खोलो", "తెరువు", "খুলুন", "उघडा", "खोल",
    # Multilingual print / input / len / range
    "लिखो", "ముద్రించు", "ছাপাও", "लिहा", "छाप",
    "पढ़ो", "తీసుకో", "পড়ো", "वाचा", "पढ",
    "लंबाई", "పొడవు", "দৈর্ঘ্য", "लांबी", "लम्बाइ",
    "सीमा", "పరిధి", "পরিসীমা", "पल्ला",
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
    "__import__", "os", "sys", "subprocess", "math", "time", "re", "json",
    # Dangerous builtins & system stubs (Stage 11 analyzes, Stage 13 stubs them)
    "execute_command", "run_shell", "system_command", "dispatch_system_command",
    "system_backup_tar_dispatch", "restore_filesystem_archive", "system", "popen",
    "file_write", "write_file",
    "network_call", "http_request", "http_get", "http_post", "socket_connect", "fetch", "socket",
    "execute_database_query", "database_query", "execute_query", "query", "sql_query",
    "dynamic_expression_evaluator"
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


def _extract_target_names(target: ast.AST) -> List[str]:
    """Recursively extract variable names from assignment target AST nodes."""
    names = []
    if isinstance(target, ast.Name):
        names.append(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            names.extend(_extract_target_names(elt))
    elif isinstance(target, ast.Starred):
        names.extend(_extract_target_names(target.value))
    return names


class SemanticAnalyzer(ast.NodeVisitor):
    """
    Performs context-sensitive semantic analysis on the generated AST with strict lexical scoping.
    Checks for undeclared identifiers across all supported languages, constant division by zero,
    and isolates function-local scopes to prevent parameter and local variable leakage.
    """
    def __init__(self):
        self.diagnostics: List[Dict[str, Any]] = []
        self.symbols: Dict[str, Dict[str, Any]] = {}
        self.all_declared_symbols: Set[str] = set()
        self.safe_builtins: Set[str] = set()
        self.module_globals: Set[str] = set()
        self.all_module_vars: Set[str] = set()
        self.scope_stack: List[Set[str]] = []
        self.in_function: bool = False

    def analyze(self, ast_tree: ast.AST) -> Dict[str, Any]:
        self.diagnostics = []
        self.symbols = {}
        self.all_declared_symbols = set()
        self.safe_builtins = get_known_builtins()

        # Pass 1: Collect module-level function and class declarations
        module_globals: Set[str] = set()
        if isinstance(ast_tree, ast.Module):
            for stmt in ast_tree.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    module_globals.add(stmt.name)
                    self.all_declared_symbols.add(stmt.name)
                    self.symbols[stmt.name] = {
                        "name": stmt.name,
                        "type": "function",
                        "scope": "global",
                        "line": getattr(stmt, "lineno", 1),
                        "value_preview": f"def {stmt.name}(...)"
                    }
                elif isinstance(stmt, ast.ClassDef):
                    module_globals.add(stmt.name)
                    self.all_declared_symbols.add(stmt.name)
                    self.symbols[stmt.name] = {
                        "name": stmt.name,
                        "type": "class",
                        "scope": "global",
                        "line": getattr(stmt, "lineno", 1),
                        "value_preview": f"class {stmt.name}"
                    }

        # Collect all top-level assigned variables for function scope access
        all_module_vars: Set[str] = set(module_globals)
        if isinstance(ast_tree, ast.Module):
            for stmt in ast_tree.body:
                if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    targets = stmt.targets if hasattr(stmt, "targets") else [stmt.target]
                    for t in targets:
                        for name in _extract_target_names(t):
                            all_module_vars.add(name)
                            self.all_declared_symbols.add(name)
                elif isinstance(stmt, ast.For):
                    for name in _extract_target_names(stmt.target):
                        all_module_vars.add(name)
                        self.all_declared_symbols.add(name)

        self.module_globals = module_globals
        self.all_module_vars = all_module_vars

        # Current scope stack: list of Sets of local names
        self.scope_stack = [set(module_globals)]
        self.in_function = False

        if isinstance(ast_tree, ast.Module):
            for stmt in ast_tree.body:
                self.visit(stmt)
        else:
            self.visit(ast_tree)

        warning_count = sum(1 for d in self.diagnostics if d["type"] == "warning")
        error_count = sum(1 for d in self.diagnostics if d["type"] == "error")

        return {
            "diagnostics": self.diagnostics,
            "symbols": self.symbols,
            "warning_count": warning_count,
            "error_count": error_count
        }

    def _is_name_in_scope(self, name: str) -> bool:
        if name in self.safe_builtins:
            return True
        for scope in reversed(self.scope_stack):
            if name in scope:
                return True
        if self.in_function and name in self.all_module_vars:
            return True
        return False

    def _record_error(self, name: str, node: ast.AST):
        line = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0) + 1
        candidates = [n for n in self.all_declared_symbols if n != name]
        close_matches = difflib.get_close_matches(name, candidates, n=1, cutoff=0.4)
        suggestion = close_matches[0] if close_matches else None
        if suggestion:
            msg = f"Identifier '{name}' at line {line}:{col} referenced before explicit local assignment. Did you mean '{suggestion}'?"
            rem = f"Declare '{name}' before use, or replace with '{suggestion}'."
        else:
            msg = f"Identifier '{name}' at line {line}:{col} referenced before explicit local assignment."
            rem = f"Declare identifier '{name}' with 'let' before referencing it in this scope."

        self.diagnostics.append({
            "type": "error",
            "line": line,
            "column": col,
            "rule_id": "SEC-SEM-001",
            "identifier": name,
            "suggestion": suggestion,
            "message": msg,
            "explanation": f"Identifier '{name}' is referenced without declaration or assignment in this lexical scope.",
            "remediation": rem
        })

    def visit_FunctionDef(self, node: ast.FunctionDef):
        func_scope = set()
        # Add parameters
        for arg in getattr(node.args, "args", []):
            func_scope.add(arg.arg)
            self.all_declared_symbols.add(arg.arg)
            self.symbols[arg.arg] = {
                "name": arg.arg,
                "type": "parameter",
                "scope": "local",
                "line": getattr(arg, "lineno", getattr(node, "lineno", 1)),
                "value_preview": f"param {arg.arg}"
            }
        if getattr(node.args, "vararg", None):
            func_scope.add(node.args.vararg.arg)
        if getattr(node.args, "kwarg", None):
            func_scope.add(node.args.kwarg.arg)
        for arg in getattr(node.args, "kwonlyargs", []):
            func_scope.add(arg.arg)

        prev_in_function = self.in_function
        self.in_function = True
        self.scope_stack.append(func_scope)

        for stmt in node.body:
            self.visit(stmt)

        self.scope_stack.pop()
        self.in_function = prev_in_function

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        class_scope = set()
        self.scope_stack.append(class_scope)
        for stmt in node.body:
            self.visit(stmt)
        self.scope_stack.pop()

    def visit_Assign(self, node: ast.Assign):
        # 1. Visit RHS value first
        self.visit(node.value)
        # 2. Add targets to current scope
        for target in node.targets:
            if isinstance(target, ast.Subscript):
                self.visit(target.value)
                self.visit(target.slice)
            elif isinstance(target, ast.Attribute):
                self.visit(target.value)

            names = _extract_target_names(target)
            for name in names:
                self.scope_stack[-1].add(name)
                self.all_declared_symbols.add(name)
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
                self.symbols[name] = {
                    "name": name,
                    "type": inferred_type,
                    "scope": "local" if self.in_function else "global",
                    "line": getattr(node, "lineno", 1),
                    "value_preview": val_preview
                }

    def visit_AugAssign(self, node: ast.AugAssign):
        if isinstance(node.target, ast.Name):
            if not self._is_name_in_scope(node.target.id):
                self._record_error(node.target.id, node.target)
        else:
            self.visit(node.target)
        self.visit(node.value)
        for name in _extract_target_names(node.target):
            self.scope_stack[-1].add(name)
            self.all_declared_symbols.add(name)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if node.value:
            self.visit(node.value)
        for name in _extract_target_names(node.target):
            self.scope_stack[-1].add(name)
            self.all_declared_symbols.add(name)

    def visit_For(self, node: ast.For):
        self.visit(node.iter)
        for name in _extract_target_names(node.target):
            self.scope_stack[-1].add(name)
            self.all_declared_symbols.add(name)
            self.symbols[name] = {
                "name": name,
                "type": "iterator",
                "scope": "local" if self.in_function else "global",
                "line": getattr(node, "lineno", 1),
                "value_preview": "for loop var"
            }
        for stmt in node.body:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)

    def visit_While(self, node: ast.While):
        self.visit(node.test)
        for stmt in node.body:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)

    def visit_If(self, node: ast.If):
        self.visit(node.test)
        for stmt in node.body:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)

    def visit_Try(self, node: ast.Try):
        for stmt in node.body:
            self.visit(stmt)
        for handler in node.handlers:
            self.visit_ExceptHandler(handler)
        for stmt in node.orelse:
            self.visit(stmt)
        for stmt in node.finalbody:
            self.visit(stmt)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        if node.type:
            self.visit(node.type)
        if node.name:
            self.scope_stack[-1].add(node.name)
            self.all_declared_symbols.add(node.name)
        for stmt in node.body:
            self.visit(stmt)

    def visit_With(self, node: ast.With):
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars:
                for name in _extract_target_names(item.optional_vars):
                    self.scope_stack[-1].add(name)
                    self.all_declared_symbols.add(name)
        for stmt in node.body:
            self.visit(stmt)

    def visit_BinOp(self, node: ast.BinOp):
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
        self.visit(node.left)
        self.visit(node.right)

    def visit_Name(self, node: ast.Name):
        if isinstance(node.ctx, ast.Load):
            if not self._is_name_in_scope(node.id):
                self._record_error(node.id, node)

