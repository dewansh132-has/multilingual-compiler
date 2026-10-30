# -*- coding: utf-8 -*-
"""
web/ai_assistant.py — Real-Time AI Programming Assistant for VITAL Web IDE

Contribution 6: Real-Time AI Programming Assistant
Provides intelligent, read-only developer assistance for the VITAL Multilingual
Programming Language Compiler.

KEY ARCHITECTURAL PRINCIPLES:
  1. STRICTLY ADVISORY: The AI NEVER modifies user source code, never writes
     files, and provides no auto-patching or auto-fixing mechanisms.
  2. COMPILER AS AUTHORITY: The existing VITAL compiler pipeline remains the
     sole authoritative compilation and execution engine.
  3. COMPILER-AWARE REASONING: Analyzes source code alongside genuine compiler
     artifacts (tokens, parser logs, AST structure, symbol table).
  4. ZERO SENSITIVE DATA EXPOSURE: Credentials stay on the backend; request
     payloads are validated and capped.
  5. ROBUST PROVIDER HANDLING: Supports Google Gemini, OpenAI, or Mock provider
     with graceful degradation when keys are unconfigured or offline.
"""

import os
import sys
import re
import json
import time
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(PROJECT_ROOT, 'src')
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from main import Compiler, RULES_FILE
from lexer import VitalLexer, Token, TokenType

# Request limits
MAX_SOURCE_LENGTH = 65536  # 64 KB limit
DEFAULT_TIMEOUT_SECONDS = 12.0

VITAL_LANGUAGE_PROMPT = """You are the AI Programming Assistant for the VITAL Multilingual Programming Language.
VITAL is an educational, rule-based multilingual programming language compiler supporting six languages:
English, Hindi (हिन्दी), Telugu (తెలుగు), Bengali (বাংলা), Marathi (मराठी), and Nepali (नेपाली).

Language Syntax Rules:
- Variables: 'let x = 10' (English), 'मानो x = 10' (Hindi), 'అనుకో x = 10' (Telugu), 'ধরো x = 10' (Bengali), 'घ्या x = 10' (Marathi), 'मान x = 10' (Nepali).
- Print: 'print(x)' (English), 'लिखो(x)' (Hindi), 'రాయి(x)' (Telugu), 'ছাপাও(x)' (Bengali), 'लिहा(x)' (Marathi), 'छाप(x)' (Nepali).
- Conditionals: 'if (cond) { ... } else { ... }' with language equivalents:
  - Hindi: 'अगर (cond) { ... } अन्यथा { ... }'
  - Telugu: 'ఒకవేళ (cond) { ... } లేకపోతే { ... }'
  - Bengali: 'যদি (cond) { ... } নাহলে { ... }'
  - Marathi: 'जर (cond) { ... } नाहीतर { ... }'
  - Nepali: 'यदि (cond) { ... } नत्र { ... }'
- Loops: 'while (cond) { ... }'
  - Hindi: 'जबतक (cond) { ... }'
  - Telugu: 'వరకు (cond) { ... }'
  - Bengali: 'যতক্ষণ (cond) { ... }'
  - Marathi: 'जोपर्यंत (cond) { ... }'
  - Nepali: 'जहिलेसम्म (cond) { ... }'
- Blocks use '{' and '}'. Expressions are standard arithmetic (+, -, *, /, ==, !=, >, <, >=, <=) or verbal operators.

CRITICAL INSTRUCTIONS:
1. You are STRICTLY ADVISORY. You NEVER modify user source code, never auto-patch, and never write files.
2. DETECT ALL ERRORS: Identify and report EVERY distinct error, bug, syntax problem, semantic issue, or warning you can find in the entire source code. DO NOT STOP after finding the first error.
3. Examine different source locations and report a separate finding object for each detectable issue.
4. Distinguish syntax errors, semantic issues (e.g. undefined variables, type mismatches), suspicious patterns (e.g. assignment in condition, infinite loops), and style/quality suggestions.
5. Provide a clear, separate explanation and actionable manual suggestion for each finding.
6. Avoid repeating the same issue in multiple findings. Do NOT invent errors to reach an arbitrary count.
7. Return pure JSON without Markdown fences matching this schema:
{
  "summary": "Found X potential issues: Y errors, Z warnings",
  "analysis_summary": "Detailed overview of all detected code issues",
  "findings": [
    {
      "category": "syntax" | "semantic" | "suspicious" | "quality" | "compiler_error",
      "severity": "error" | "warning" | "info" | "tip",
      "line": 1,
      "column": 7,
      "location": "Line 1, Column 7",
      "title": "Clear finding title",
      "message": "Description of the issue",
      "explanation": "Detailed pedagogical explanation of what is happening and why",
      "suggestion": "What manual action the user should take",
      "suggested_code": "Read-only example code showing the corrected pattern",
      "why": "Explanation of why this manual correction works",
      "is_compiler_diagnostic": false,
      "confidence": "high" | "medium" | "low"
    }
  ],
  "pedagogical_note": "A helpful tip or concept explanation for the programmer"
}
"""


class ReadOnlyAnalysisTools:
    """
    Read-only static analysis tools inspecting compiler state and source code.
    Guaranteed to have NO write, execute, or mutate operations.
    """

    @staticmethod
    def get_lexer_tokens(source_code: str) -> Dict[str, Any]:
        """Safely tokenize source code using existing VITAL lexer."""
        try:
            compiler = Compiler(RULES_FILE)
            compiler.load_rules()
            tokens: List[Token] = compiler.lexer.tokenize(source_code)
            
            token_summary = []
            for t in tokens:
                if t.type != TokenType.EOF:
                    token_summary.append({
                        "type": t.type.name,
                        "lexeme": t.lexeme,
                        "line": t.line,
                        "column": t.column,
                        "token_name": t.token_name
                    })
            return {
                "success": True,
                "total_tokens": len(token_summary),
                "tokens": token_summary[:80]  # Cap summary to avoid context bloat
            }
        except Exception as e:
            return {"success": False, "error": str(e), "tokens": []}

    @staticmethod
    def check_bracket_balance(source_code: str) -> List[Dict[str, Any]]:
        """Static delimiter matching with line and column numbers."""
        findings = []
        lines = source_code.splitlines()
        brace_stack = []
        paren_stack = []
        bracket_stack = []

        for line_no, line in enumerate(lines, start=1):
            in_str = False
            str_char = None
            escaped = False
            col_no = 0
            while col_no < len(line):
                ch = line[col_no]
                # Check for comment start outside string
                if not in_str and (ch == '#' or (ch == '/' and col_no + 1 < len(line) and line[col_no + 1] == '/')):
                    break
                # String tracking
                if in_str:
                    if escaped:
                        escaped = False
                    elif ch == '\\':
                        escaped = True
                    elif ch == str_char:
                        in_str = False
                        str_char = None
                else:
                    if ch in ('"', "'"):
                        in_str = True
                        str_char = ch
                    elif ch == '{':
                        brace_stack.append((line_no, col_no + 1))
                    elif ch == '}':
                        if brace_stack:
                            brace_stack.pop()
                        else:
                            findings.append({
                                "category": "syntax",
                                "severity": "error",
                                "line": line_no,
                                "column": col_no + 1,
                                "location": f"Line {line_no}, Column {col_no + 1}",
                                "title": "Unmatched Closing Brace '}'",
                                "message": f"Found closing brace '}}' without matching opening brace '{{' at Line {line_no}, Column {col_no + 1}",
                                "explanation": f"Found closing brace '}}' without a corresponding opening brace '{{'.",
                                "suggestion": "Remove the unexpected closing brace or verify block nesting.",
                                "suggested_code": "// Remove unexpected closing brace or check block scope",
                                "why": "Every closing brace must match a prior opening brace in VITAL blocks.",
                                "is_compiler_diagnostic": True,
                                "confidence": "high"
                            })
                    elif ch == '(':
                        paren_stack.append((line_no, col_no + 1))
                    elif ch == ')':
                        if paren_stack:
                            paren_stack.pop()
                        else:
                            findings.append({
                                "category": "syntax",
                                "severity": "error",
                                "line": line_no,
                                "column": col_no + 1,
                                "location": f"Line {line_no}, Column {col_no + 1}",
                                "title": "Unmatched Closing Parenthesis ')'",
                                "message": f"Found closing parenthesis ')' without matching opening '(' at Line {line_no}, Column {col_no + 1}",
                                "explanation": f"Found closing parenthesis ')' without a corresponding opening '('.",
                                "suggestion": "Remove the unexpected closing parenthesis or check expression balance.",
                                "suggested_code": "// Remove unexpected closing parenthesis",
                                "why": "Parentheses in conditions and function calls must be balanced.",
                                "is_compiler_diagnostic": True,
                                "confidence": "high"
                            })
                    elif ch == '[':
                        bracket_stack.append((line_no, col_no + 1))
                    elif ch == ']':
                        if bracket_stack:
                            bracket_stack.pop()
                        else:
                            findings.append({
                                "category": "syntax",
                                "severity": "error",
                                "line": line_no,
                                "column": col_no + 1,
                                "location": f"Line {line_no}, Column {col_no + 1}",
                                "title": "Unmatched Closing Square Bracket ']'",
                                "message": f"Found closing bracket ']' without matching opening '[' at Line {line_no}, Column {col_no + 1}",
                                "explanation": f"Found closing square bracket ']' without a corresponding opening '['.",
                                "suggestion": "Remove the unexpected closing bracket or check list indexing.",
                                "suggested_code": "// Remove unexpected closing bracket",
                                "why": "Square brackets must be balanced in expressions and indexing.",
                                "is_compiler_diagnostic": True,
                                "confidence": "high"
                            })
                col_no += 1

        for (l_no, c_no) in brace_stack:
            findings.append({
                "category": "syntax",
                "severity": "error",
                "line": l_no,
                "column": c_no,
                "location": f"Line {l_no}, Column {c_no}",
                "title": "Unclosed Opening Brace '{'",
                "message": f"Block opened with '{{' on Line {l_no}, Column {c_no} was never closed",
                "explanation": f"Block opened with '{{' on Line {l_no} was never closed with '}}'.",
                "suggestion": "Add a closing brace '}' to terminate the block scope.",
                "suggested_code": "}\n// Add closing brace to terminate block scope",
                "why": "VITAL blocks (for if, while, functions) require an explicit closing brace.",
                "is_compiler_diagnostic": True,
                "confidence": "high"
            })

        for (l_no, c_no) in paren_stack:
            findings.append({
                "category": "syntax",
                "severity": "error",
                "line": l_no,
                "column": c_no,
                "location": f"Line {l_no}, Column {c_no}",
                "title": "Unclosed Opening Parenthesis '('",
                "message": f"Expression opened with '(' on Line {l_no}, Column {c_no} was never closed",
                "explanation": f"Expression opened with '(' on Line {l_no} was never closed with ')'.",
                "suggestion": "Add a closing parenthesis ')' to complete the expression.",
                "suggested_code": ")\n// Add closing parenthesis to finish expression",
                "why": "Conditions and print statements require balanced parentheses.",
                "is_compiler_diagnostic": True,
                "confidence": "high"
            })

        for (l_no, c_no) in bracket_stack:
            findings.append({
                "category": "syntax",
                "severity": "error",
                "line": l_no,
                "column": c_no,
                "location": f"Line {l_no}, Column {c_no}",
                "title": "Unclosed Opening Square Bracket '['",
                "message": f"Bracket opened with '[' on Line {l_no}, Column {c_no} was never closed",
                "explanation": f"Bracket opened with '[' on Line {l_no} was never closed with ']'.",
                "suggestion": "Add a closing bracket ']' to complete the index or array.",
                "suggested_code": "]\n// Add closing bracket",
                "why": "Square brackets must be balanced.",
                "is_compiler_diagnostic": True,
                "confidence": "high"
            })

        return findings

    @staticmethod
    def check_string_literals(source_code: str) -> List[Dict[str, Any]]:
        """Inspects for unclosed string literals on each line."""
        findings = []
        lines = source_code.splitlines()
        for line_no, line in enumerate(lines, start=1):
            in_string = False
            quote_char = None
            quote_col = 0
            escaped = False
            col = 0
            while col < len(line):
                ch = line[col]
                # Check for comment outside string
                if not in_string and (ch == '#' or (ch == '/' and col + 1 < len(line) and line[col + 1] == '/')):
                    break
                if in_string:
                    if escaped:
                        escaped = False
                    elif ch == '\\':
                        escaped = True
                    elif ch == quote_char:
                        in_string = False
                        quote_char = None
                else:
                    if ch in ('"', "'"):
                        in_string = True
                        quote_char = ch
                        quote_col = col + 1
                col += 1
            if in_string:
                findings.append({
                    "category": "syntax",
                    "severity": "error",
                    "line": line_no,
                    "column": quote_col,
                    "location": f"Line {line_no}, Column {quote_col}",
                    "title": "Unclosed String Literal",
                    "message": f"String opened with {quote_char} is not terminated on this line",
                    "explanation": f"The string literal starting with {quote_char} on Line {line_no} is missing a closing quote before the line ends.",
                    "suggestion": f"Add a closing {quote_char} to terminate the string literal.",
                    "suggested_code": f'{line.rstrip()}{quote_char}\n// Add closing {quote_char}',
                    "why": "In VITAL, single-line string literals must be properly terminated with matching quotes.",
                    "is_compiler_diagnostic": False,
                    "confidence": "high"
                })
        return findings

    @staticmethod
    def check_undefined_variables(source_code: str) -> List[Dict[str, Any]]:
        """Inspects for identifiers referenced before declaration or initialization."""
        findings = []
        try:
            compiler = Compiler(RULES_FILE)
            compiler.load_rules()
            tokens = compiler.lexer.tokenize(source_code)
        except Exception:
            return findings

        built_in_names = set(compiler.translation_map.keys()) | {
            "print", "input", "len", "range", "int", "str", "float", "bool",
            "true", "false", "null", "True", "False", "None"
        }

        declared_vars = set()
        reported_vars = set()
        n = len(tokens)
        i = 0

        while i < n:
            tok = tokens[i]
            if tok.type == TokenType.EOF:
                break

            # 1. Variable declaration keyword (let, मानो, etc.)
            if tok.type == TokenType.KEYWORD and tok.token_name == "TOKEN_VAR_DECLARE":
                j = i + 1
                if j < n and tokens[j].type == TokenType.IDENTIFIER:
                    declared_vars.add(tokens[j].lexeme)
                    i = j + 1
                    if i < n and tokens[i].type == TokenType.OPERATOR and tokens[i].lexeme == '=':
                        i += 1
                    continue

            # 2. Function declaration (def / function func_name(param1, param2))
            if tok.type == TokenType.KEYWORD and tok.token_name == "TOKEN_FUNCTION":
                j = i + 1
                if j < n and tokens[j].type == TokenType.IDENTIFIER:
                    declared_vars.add(tokens[j].lexeme)
                    j += 1
                if j < n and tokens[j].lexeme == '(':
                    j += 1
                    while j < n and tokens[j].lexeme != ')':
                        if tokens[j].type == TokenType.IDENTIFIER:
                            declared_vars.add(tokens[j].lexeme)
                        j += 1
                i = j + 1
                continue

            # 3. Direct assignment: identifier = expr
            if tok.type == TokenType.IDENTIFIER:
                if i + 1 < n and tokens[i + 1].type == TokenType.OPERATOR and tokens[i + 1].lexeme == '=':
                    declared_vars.add(tok.lexeme)
                    i += 2
                    continue

                # Identifier in expression context
                var_name = tok.lexeme
                if var_name not in declared_vars and var_name not in built_in_names and var_name not in reported_vars:
                    reported_vars.add(var_name)
                    findings.append({
                        "category": "semantic",
                        "severity": "error",
                        "line": tok.line,
                        "column": tok.column,
                        "location": f"Line {tok.line}, Column {tok.column}",
                        "title": f"Undefined Variable '{var_name}'",
                        "message": f"Variable '{var_name}' appears to be used before declaration",
                        "explanation": f"The variable '{var_name}' appears to be used before declaration or initialization.",
                        "suggestion": f"Check whether '{var_name}' was declared correctly or initialize it with 'let {var_name} = ...'.",
                        "suggested_code": f"let {var_name} = 0\n// Declare or initialize '{var_name}' before this statement",
                        "why": "In VITAL, variables must be declared or initialized before they are evaluated in expressions or function calls.",
                        "is_compiler_diagnostic": False,
                        "confidence": "high"
                    })

            i += 1

        return findings

    @staticmethod
    def check_syntax_expressions(source_code: str) -> List[Dict[str, Any]]:
        """Inspects for syntax and expression errors (consecutive operators, dangling operators, malformed statements)."""
        findings = []
        try:
            compiler = Compiler(RULES_FILE)
            compiler.load_rules()
            tokens = compiler.lexer.tokenize(source_code)
        except Exception:
            return findings

        binary_ops = {'+', '-', '*', '/', '%', '==', '!=', '>', '<', '>=', '<='}
        n = len(tokens)

        for i in range(n):
            tok = tokens[i]
            if tok.type == TokenType.EOF:
                break

            # A. Declaration keyword without identifier
            if tok.type == TokenType.KEYWORD and tok.token_name == "TOKEN_VAR_DECLARE":
                if i + 1 < n:
                    next_tok = tokens[i + 1]
                    if next_tok.type != TokenType.IDENTIFIER and next_tok.type != TokenType.EOF and next_tok.line == tok.line:
                        findings.append({
                            "category": "syntax",
                            "severity": "error",
                            "line": tok.line,
                            "column": tok.column,
                            "location": f"Line {tok.line}, Column {tok.column}",
                            "title": "Syntax Error: Missing Variable Identifier",
                            "message": f"Declaration keyword '{tok.lexeme}' must be followed by a variable identifier",
                            "explanation": f"The variable declaration keyword '{tok.lexeme}' is followed by '{next_tok.lexeme}' instead of a variable name.",
                            "suggestion": f"Specify a variable name, e.g. '{tok.lexeme} varName = ...'.",
                            "suggested_code": f"{tok.lexeme} x = 0",
                            "why": "Variable declarations require an identifier name between the declaration keyword and assignment operator.",
                            "is_compiler_diagnostic": False,
                            "confidence": "high"
                        })

            # B. Consecutive binary operators (e.g. + *, * /)
            if tok.type == TokenType.OPERATOR and tok.lexeme in binary_ops:
                if i + 1 < n:
                    next_tok = tokens[i + 1]
                    if next_tok.type == TokenType.OPERATOR and next_tok.lexeme in binary_ops:
                        # Allow unary minus only if followed by number or identifier
                        if next_tok.lexeme == '-' and i + 2 < n and tokens[i + 2].type in (TokenType.NUMBER, TokenType.IDENTIFIER):
                            pass
                        else:
                            findings.append({
                                "category": "syntax",
                                "severity": "error",
                                "line": next_tok.line,
                                "column": next_tok.column,
                                "location": f"Line {next_tok.line}, Column {next_tok.column}",
                                "title": "Invalid Expression: Consecutive Operators",
                                "message": f"Found consecutive operators '{tok.lexeme}' and '{next_tok.lexeme}'",
                                "explanation": f"The expression contains consecutive operators '{tok.lexeme}' and '{next_tok.lexeme}' without an operand between them.",
                                "suggestion": "Review the expression and remove the duplicate or misplaced operator.",
                                "suggested_code": f"// Remove extra operator '{next_tok.lexeme}' or supply intermediate value",
                                "why": "Binary operators require operands on both sides to form a valid arithmetic or comparison expression.",
                                "is_compiler_diagnostic": False,
                                "confidence": "high"
                            })

            # C. Leading binary operator after = (e.g. let x = * 5)
            if tok.type == TokenType.OPERATOR and tok.lexeme == '=':
                if i + 1 < n:
                    next_tok = tokens[i + 1]
                    if next_tok.type == TokenType.OPERATOR and next_tok.lexeme in {'*', '/', '%', '==', '!=', '>', '<', '>=', '<='}:
                        findings.append({
                            "category": "syntax",
                            "severity": "error",
                            "line": next_tok.line,
                            "column": next_tok.column,
                            "location": f"Line {next_tok.line}, Column {next_tok.column}",
                            "title": "Invalid Expression: Unexpected Leading Operator",
                            "message": f"Expression cannot begin with operator '{next_tok.lexeme}'",
                            "explanation": f"The binary operator '{next_tok.lexeme}' appears at the beginning of an expression without a left operand.",
                            "suggestion": f"Remove '{next_tok.lexeme}' or place a value before it.",
                            "suggested_code": f"// Remove leading '{next_tok.lexeme}'",
                            "why": "Binary operators like '*' and '/' require a preceding left operand.",
                            "is_compiler_diagnostic": False,
                            "confidence": "high"
                        })

            # D. Trailing operator at end of line (e.g. let x = 5 +)
            if tok.type == TokenType.OPERATOR and tok.lexeme in binary_ops:
                line_toks = [t for t in tokens if t.line == tok.line and t.type not in (TokenType.COMMENT, TokenType.EOF)]
                if line_toks and line_toks[-1] == tok:
                    findings.append({
                        "category": "syntax",
                        "severity": "error",
                        "line": tok.line,
                        "column": tok.column,
                        "location": f"Line {tok.line}, Column {tok.column}",
                        "title": "Invalid Expression: Incomplete Statement",
                        "message": f"Statement ends with trailing operator '{tok.lexeme}'",
                        "explanation": f"The statement terminates with operator '{tok.lexeme}' without a right-hand operand.",
                        "suggestion": f"Provide the missing right-hand operand after '{tok.lexeme}'.",
                        "suggested_code": f"// Complete the expression after '{tok.lexeme}'",
                        "why": "Expressions ending abruptly with binary operators are incomplete and fail parsing.",
                        "is_compiler_diagnostic": False,
                        "confidence": "high"
                    })

            # E. Empty condition in if / while / elif: if () {
            if tok.type == TokenType.KEYWORD and tok.token_name in ("TOKEN_IF", "TOKEN_LOOP_WHILE", "TOKEN_ELIF"):
                if i + 1 < n and tokens[i + 1].lexeme == '(':
                    if i + 2 < n and tokens[i + 2].lexeme == ')':
                        findings.append({
                            "category": "syntax",
                            "severity": "error",
                            "line": tok.line,
                            "column": tokens[i + 1].column,
                            "location": f"Line {tok.line}, Column {tokens[i + 1].column}",
                            "title": "Syntax Error: Empty Condition",
                            "message": f"Conditional statement '{tok.lexeme}' has an empty condition",
                            "explanation": f"The condition for '{tok.lexeme}' in parentheses is empty.",
                            "suggestion": "Specify a boolean condition inside parentheses, e.g. '(x > 0)'.",
                            "suggested_code": f"{tok.lexeme} (condition) {{\n    // block\n}}",
                            "why": "Conditional and loop structures require a non-empty boolean expression to evaluate.",
                            "is_compiler_diagnostic": False,
                            "confidence": "high"
                        })

        return findings

    @staticmethod
    def inspect_suspicious_patterns(source_code: str) -> List[Dict[str, Any]]:
        """Static inspection for common code smell, infinite loops, and quality issues."""
        findings = []
        lines = source_code.splitlines()

        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            
            # Check for assignment in condition, e.g. if (x = 5)
            assign_in_cond = re.search(r'(?:if|अगर|ఒకవేళ|যদি|जर|यदि)\s*\([^=!<>]*(?<![=!<>])=([^=].*)\)', stripped)
            if assign_in_cond:
                findings.append({
                    "category": "suspicious",
                    "severity": "warning",
                    "line": line_no,
                    "location": f"Line {line_no}",
                    "title": "Possible Assignment in Conditional Statement",
                    "explanation": "You appear to be using '=' (assignment) inside a conditional check. In VITAL, '==' is used for equality checks.",
                    "suggested_code": stripped.replace("=", "==", 1),
                    "why": "Using '=' in a condition is usually unintended and may cause unexpected truthiness evaluation.",
                    "is_compiler_diagnostic": False,
                    "confidence": "high"
                })

            # Check for likely infinite loop: while (true) or while (1) without break
            while_true = re.search(r'(?:while|जबतक|వరకు|যতক্ষণ|जोपर्यंत|जहिलेसम्म)\s*\(\s*(?:true|1|True)\s*\)', stripped)
            if while_true:
                findings.append({
                    "category": "suspicious",
                    "severity": "warning",
                    "line": line_no,
                    "location": f"Line {line_no}",
                    "title": "Potential Infinite Loop Condition",
                    "explanation": "This loop has a constant true condition. Ensure there is an update variable or break statement inside the loop body.",
                    "suggested_code": "// Ensure loop variables are updated inside the block, or use a terminating condition",
                    "why": "Unbounded loops without termination conditions will trigger compiler execution timeouts.",
                    "is_compiler_diagnostic": False,
                    "confidence": "medium"
                })

            # Check for division by zero literal
            div_zero = re.search(r'/\s*0(?![0-9.])', stripped)
            if div_zero:
                findings.append({
                    "category": "semantic",
                    "severity": "error",
                    "line": line_no,
                    "location": f"Line {line_no}",
                    "title": "Division by Zero Detected",
                    "explanation": "Expression divides a value by literal 0, which will cause a ZeroDivisionError at runtime.",
                    "suggested_code": "// Replace denominator with a non-zero value or check denominator > 0",
                    "why": "Division by zero is undefined in mathematics and causes a runtime crash in the execution engine.",
                    "is_compiler_diagnostic": False,
                    "confidence": "high"
                })

        return findings

    @staticmethod
    def detect_homoglyphs(source_code: str) -> List[Dict[str, Any]]:
        """Inspects for multilingual homoglyphs that might disguise syntax."""
        homoglyphs = {
            'ः': ('Colon', ':'),
            '।': ('Pipe/Danda', '|'),
            '०': ('Latin letter o', 'o'),
            'ऽ': ('Latin letter S', 'S')
        }
        findings = []
        for line_no, line in enumerate(source_code.splitlines(), start=1):
            for danger_char, (name, expected) in homoglyphs.items():
                if danger_char in line:
                    findings.append({
                        "category": "suspicious",
                        "severity": "warning",
                        "line": line_no,
                        "location": f"Line {line_no}",
                        "title": f"Unicode Homoglyph '{danger_char}' ({name})",
                        "explanation": f"The character '{danger_char}' resembles '{expected}' but has a different Unicode value. The compiler normalizes this, but it may cause visual confusion.",
                        "suggested_code": line.replace(danger_char, expected),
                        "why": "Using standard ASCII syntax punctuation avoids confusion across different text editors and fonts.",
                        "is_compiler_diagnostic": False,
                        "confidence": "high"
                    })
        return findings


class VitalAIAssistant:
    """
    Real-Time AI Programming Assistant Engine.
    Coordinates local compiler-backed static inspection and optional LLM reasoning.
    """

    def __init__(self):
        self.provider = self._detect_provider()

    def _detect_provider(self) -> str:
        """Determines the active AI provider based on environment variables."""
        if os.environ.get("VITAL_AI_MOCK") in ("1", "true", "TRUE"):
            return "mock"
        if os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
            return "gemini"
        if os.environ.get("OPENAI_API_KEY"):
            return "openai"
        return "unconfigured"

    def get_status(self) -> Dict[str, Any]:
        """Returns the current assistant configuration and capabilities."""
        provider = self._detect_provider()
        return {
            "configured": provider != "unconfigured",
            "provider": provider,
            "model": self._get_active_model_name(provider),
            "real_time_analysis": True,
            "read_only_mode": True,
            "disclaimer": "AI suggestions are strictly advisory. Your code is never modified automatically."
        }

    def _get_active_model_name(self, provider: str) -> str:
        if provider == "gemini":
            return os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
        elif provider == "openai":
            return os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        elif provider == "mock":
            return "vital-mock-assistant-v1"
        return "none"

    def analyze(
        self,
        source_code: str,
        diagnostics: Optional[Dict[str, Any]] = None,
        language: str = "English",
        source_version: int = 1
    ) -> Dict[str, Any]:
        """
        Analyzes source code and produces structured, read-only advisory suggestions.
        """
        # 1. Input Validation
        if not source_code or not source_code.strip():
            return {
                "success": False,
                "error": "Empty source code",
                "source_version": source_version,
                "analysis_summary": "Editor is empty. Enter or select VITAL code to receive analysis.",
                "findings": [],
                "disclaimer": "AI suggestions are advisory. Your code is never modified automatically."
            }

        if len(source_code) > MAX_SOURCE_LENGTH:
            return {
                "success": False,
                "error": f"Source code exceeds maximum permitted length of {MAX_SOURCE_LENGTH} bytes",
                "source_version": source_version,
                "analysis_summary": "Code exceeds maximum size limit for analysis.",
                "findings": [],
                "disclaimer": "AI suggestions are advisory. Your code is never modified automatically."
            }

        # 2. Local Compiler-Aware Static Inspections (Always available & 100% reliable)
        bracket_findings = ReadOnlyAnalysisTools.check_bracket_balance(source_code)
        string_findings = ReadOnlyAnalysisTools.check_string_literals(source_code)
        undefined_var_findings = ReadOnlyAnalysisTools.check_undefined_variables(source_code)
        syntax_findings = ReadOnlyAnalysisTools.check_syntax_expressions(source_code)
        suspicious_findings = ReadOnlyAnalysisTools.inspect_suspicious_patterns(source_code)
        homoglyph_findings = ReadOnlyAnalysisTools.detect_homoglyphs(source_code)

        base_findings: List[Dict[str, Any]] = []
        base_findings.extend(bracket_findings)
        base_findings.extend(string_findings)
        base_findings.extend(undefined_var_findings)
        base_findings.extend(syntax_findings)
        base_findings.extend(suspicious_findings)
        base_findings.extend(homoglyph_findings)

        # 3. Incorporate Compiler Diagnostics if provided
        if diagnostics:
            comp_findings = self._extract_compiler_findings(diagnostics)
            base_findings = self._merge_findings(base_findings, comp_findings)

        # 4. Check Provider
        current_provider = self._detect_provider()

        if current_provider == "unconfigured":
            # Calculate counts
            err_count = sum(1 for f in base_findings if (f.get("severity") or "").lower() == "error")
            warn_count = sum(1 for f in base_findings if (f.get("severity") or "").lower() == "warning")
            info_count = sum(1 for f in base_findings if (f.get("severity") or "").lower() in ("info", "tip", "quality"))
            total_count = len(base_findings)

            if total_count == 0:
                summary = "No issues detected. Local compiler checks passed."
            else:
                breakdown = []
                if err_count > 0:
                    breakdown.append(f"{err_count} error{'s' if err_count != 1 else ''}")
                if warn_count > 0:
                    breakdown.append(f"{warn_count} warning{'s' if warn_count != 1 else ''}")
                if info_count > 0:
                    breakdown.append(f"{info_count} suggestion{'s' if info_count != 1 else ''}")
                summary = f"Found {total_count} issue(s): {', '.join(breakdown)} via local compiler inspection. (Cloud AI unconfigured)."

            return {
                "success": True,
                "provider": "local_compiler_rules",
                "configured": False,
                "source_version": source_version,
                "summary": summary,
                "analysis_summary": summary,
                "findings": base_findings,
                "pedagogical_note": "AI suggestions are advisory. Edit your code manually in the editor.",
                "disclaimer": "AI suggestions are advisory. Your code is never modified automatically."
            }

        if current_provider == "mock":
            # Deterministic mock response for automated tests
            return self._generate_mock_analysis(source_code, base_findings, source_version)

        # 5. Live Provider Call (Gemini or OpenAI)
        try:
            if current_provider == "gemini":
                llm_result = self._call_gemini_api(source_code, diagnostics, language)
            elif current_provider == "openai":
                llm_result = self._call_openai_api(source_code, diagnostics, language)
            else:
                llm_result = None

            if llm_result and isinstance(llm_result, dict):
                merged_findings = self._merge_findings(base_findings, llm_result.get("findings", []))
                err_count = sum(1 for f in merged_findings if (f.get("severity") or "").lower() == "error")
                warn_count = sum(1 for f in merged_findings if (f.get("severity") or "").lower() == "warning")
                info_count = sum(1 for f in merged_findings if (f.get("severity") or "").lower() in ("info", "tip", "quality"))
                total_count = len(merged_findings)

                breakdown = []
                if err_count > 0:
                    breakdown.append(f"{err_count} error{'s' if err_count != 1 else ''}")
                if warn_count > 0:
                    breakdown.append(f"{warn_count} warning{'s' if warn_count != 1 else ''}")
                if info_count > 0:
                    breakdown.append(f"{info_count} suggestion{'s' if info_count != 1 else ''}")
                summary_str = llm_result.get("summary") or llm_result.get("analysis_summary")
                if not summary_str or "Found" not in summary_str:
                    summary_str = f"Found {total_count} issue(s): {', '.join(breakdown)}."

                return {
                    "success": True,
                    "provider": current_provider,
                    "configured": True,
                    "source_version": source_version,
                    "summary": summary_str,
                    "analysis_summary": summary_str,
                    "findings": merged_findings,
                    "pedagogical_note": llm_result.get("pedagogical_note", ""),
                    "disclaimer": "AI suggestions are advisory. Your code is never modified automatically."
                }
            else:
                # Fallback to local analysis if LLM response format was invalid
                return {
                    "success": True,
                    "provider": "local_fallback",
                    "configured": True,
                    "source_version": source_version,
                    "summary": f"Found {len(base_findings)} issue(s) via local compiler inspection.",
                    "analysis_summary": "LLM response format was unparsed. Showing compiler-backed findings.",
                    "findings": base_findings,
                    "pedagogical_note": "Ensure syntax conforms to VITAL multilingual keywords.",
                    "disclaimer": "AI suggestions are advisory. Your code is never modified automatically."
                }

        except Exception as e:
            # Network failure or timeout: return local findings safely without breaking IDE
            return {
                "success": True,
                "provider": "local_fallback",
                "configured": True,
                "source_version": source_version,
                "summary": f"Found {len(base_findings)} issue(s) via local compiler inspection.",
                "analysis_summary": f"Cloud AI request error ({type(e).__name__}). Showing compiler-backed findings.",
                "findings": base_findings,
                "provider_error": str(e),
                "disclaimer": "AI suggestions are advisory. Your code is never modified automatically."
            }

    def explain_error(
        self,
        source_code: str,
        error_details: Dict[str, Any],
        diagnostics: Optional[Dict[str, Any]] = None,
        language: str = "English"
    ) -> Dict[str, Any]:
        """
        Specialized explanation for compilation errors and runtime crashes.
        Explains all detectable errors rather than stopping after one.
        """
        err_msg = error_details.get("message", "") if error_details else ""
        err_type = error_details.get("type", "Error") if error_details else "Error"
        err_line = error_details.get("line") if error_details else None

        explanation = f"The compiler reported a {err_type}: {err_msg}."
        suggestion = "// Check statement syntax and delimiter matching."
        why = "Resolving syntax or runtime mismatch aligns source code with VITAL grammar."

        if "Unbalanced brackets" in err_msg:
            explanation = "Your code contains unmatched braces '{' or '}'. Every opened block must be closed."
            suggestion = "}\n// Ensure every '{' has a matching '}'"
            why = "VITAL uses braces to delineate block scopes for if/while statements."
        elif "Unbalanced parentheses" in err_msg:
            explanation = "Your code contains unmatched parentheses '(' or ')'. Every opened expression or condition must be closed."
            suggestion = ")\n// Ensure every '(' has a matching ')'"
            why = "Conditions and print statements require balanced parentheses."
        elif "division by zero" in err_msg.lower():
            explanation = "The program attempted to divide a number by zero during execution."
            suggestion = "// Guard denominator before division\nif (denom != 0) { ... }"
            why = "Division by zero produces an undefined mathematical result and crashes the runtime."

        primary_finding = {
            "category": "compiler_error",
            "severity": "error",
            "line": err_line,
            "location": f"Line {err_line}" if err_line else "Compiler Diagnostic",
            "title": f"Compiler Error: {err_type}",
            "message": err_msg,
            "explanation": explanation,
            "suggestion": suggestion,
            "suggested_code": suggestion,
            "why": why,
            "is_compiler_diagnostic": True,
            "confidence": "high"
        }

        all_findings = [primary_finding]

        # 1. Additional compiler findings from diagnostics
        if diagnostics:
            comp_findings = self._extract_compiler_findings(diagnostics)
            for cf in comp_findings:
                # Add if not duplicate of primary finding
                if cf.get("message") != primary_finding.get("message"):
                    all_findings.append(cf)

        # 2. Local source inspections to discover related/co-occurring errors in code
        bracket_findings = ReadOnlyAnalysisTools.check_bracket_balance(source_code)
        string_findings = ReadOnlyAnalysisTools.check_string_literals(source_code)
        undefined_var_findings = ReadOnlyAnalysisTools.check_undefined_variables(source_code)
        syntax_findings = ReadOnlyAnalysisTools.check_syntax_expressions(source_code)
        suspicious_findings = ReadOnlyAnalysisTools.inspect_suspicious_patterns(source_code)

        local_findings = []
        local_findings.extend(bracket_findings)
        local_findings.extend(string_findings)
        local_findings.extend(undefined_var_findings)
        local_findings.extend(syntax_findings)
        local_findings.extend(suspicious_findings)

        # Merge local findings into all_findings
        for lf in local_findings:
            # Check if this local finding represents the same underlying issue as primary finding
            title_lower = lf.get("title", "").lower()
            is_same_as_primary = False
            if "bracket" in title_lower or "brace" in title_lower:
                if "unbalanced brackets" in err_msg.lower():
                    is_same_as_primary = True
            elif "parenthes" in title_lower:
                if "unbalanced parentheses" in err_msg.lower():
                    is_same_as_primary = True
            elif "division by zero" in title_lower:
                if "division by zero" in err_msg.lower():
                    is_same_as_primary = True

            if is_same_as_primary:
                # Enrich primary finding with exact location
                if lf.get("line"):
                    primary_finding["line"] = lf.get("line")
                    primary_finding["column"] = lf.get("column")
                    primary_finding["location"] = lf.get("location")
                if lf.get("suggested_code"):
                    primary_finding["suggested_code"] = lf.get("suggested_code")
            else:
                # Distinct independent error
                all_findings.append(lf)

        # Deduplicate all_findings
        all_findings = self._merge_findings([], all_findings)

        # 3. LLM Provider Deep Reasoning (if configured)
        current_provider = self._detect_provider()
        if current_provider in ("gemini", "openai"):
            issues_summary = "\n".join([f"- {f.get('title')}: {f.get('explanation')}" for f in all_findings])
            prompt = (
                f"Explain each of the following VITAL compiler and source code errors clearly for a student.\n"
                f"Issues detected:\n{issues_summary}\n\n"
                f"Source code:\n{source_code[:3000]}\n"
                f"Language context: {language}\n"
                f"Provide clear, separate explanations and manual suggestions for each issue."
            )
            try:
                if current_provider == "gemini":
                    llm_data = self._call_gemini_api(source_code, diagnostics, language, custom_prompt=prompt)
                else:
                    llm_data = self._call_openai_api(source_code, diagnostics, language, custom_prompt=prompt)
                if llm_data and isinstance(llm_data, dict) and "findings" in llm_data and len(llm_data["findings"]) > 0:
                    all_findings = self._merge_findings(all_findings, llm_data["findings"])
            except Exception:
                pass

        total = len(all_findings)
        summary = f"Compiler Diagnostic Explanation: {total} issue(s) identified" if total > 0 else f"Compiler {err_type} Analysis: No active errors."

        return {
            "success": True,
            "error_summary": summary,
            "summary": summary,
            "findings": all_findings,
            "finding": all_findings[0] if all_findings else None,
            "pedagogical_note": "Carefully resolving each diagnostic ensures valid VITAL syntax and clean execution.",
            "disclaimer": "AI suggestions are advisory. Your code is never modified automatically."
        }

    # -------------------------------------------------------------------------
    # Internal LLM Providers (Gemini & OpenAI)
    # -------------------------------------------------------------------------
    def _call_gemini_api(
        self,
        source_code: str,
        diagnostics: Optional[Dict[str, Any]],
        language: str,
        custom_prompt: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Invokes Google Gemini REST API using urllib without extra dependencies."""
        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            return None

        model = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"

        diag_context = ""
        if diagnostics:
            diag_context = f"\nCompiler Diagnostics:\n{json.dumps(diagnostics, indent=2)[:1000]}"

        user_content = custom_prompt or (
            f"Please analyze the following VITAL programming language code.\n"
            f"Script Language context: {language}\n"
            f"{diag_context}\n\n"
            f"Source Code:\n{source_code}\n"
        )

        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": VITAL_LANGUAGE_PROMPT},
                        {"text": user_content}
                    ]
                }
            ],
            "generationConfig": {
                "responseMimeType": "application/json",
                "temperature": 0.2,
                "maxOutputTokens": 2048
            }
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT_SECONDS) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            candidate = data.get("candidates", [{}])[0]
            text = candidate.get("content", {}).get("parts", [{}])[0].get("text", "")
            return self._parse_json_response(text)

    def _call_openai_api(
        self,
        source_code: str,
        diagnostics: Optional[Dict[str, Any]],
        language: str,
        custom_prompt: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Invokes OpenAI Chat Completions REST API."""
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            return None

        model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        url = "https://api.openai.com/v1/chat/completions"

        diag_context = ""
        if diagnostics:
            diag_context = f"\nCompiler Diagnostics:\n{json.dumps(diagnostics, indent=2)[:1000]}"

        user_content = custom_prompt or (
            f"Please analyze the following VITAL programming language code.\n"
            f"Script Language context: {language}\n"
            f"{diag_context}\n\n"
            f"Source Code:\n{source_code}\n"
        )

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": VITAL_LANGUAGE_PROMPT},
                {"role": "user", "content": user_content}
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.2
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            },
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT_SECONDS) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            return self._parse_json_response(text)

    def _parse_json_response(self, text: str) -> Optional[Dict[str, Any]]:
        """Robust JSON extraction stripping markdown wrappers if present."""
        if not text:
            return None
        clean_text = text.strip()
        if clean_text.startswith("```"):
            clean_text = re.sub(r'^```(?:json)?\s*', '', clean_text)
            clean_text = re.sub(r'\s*```$', '', clean_text)
        try:
            return json.loads(clean_text)
        except Exception:
            return None

    def _generate_mock_analysis(
        self,
        source_code: str,
        base_findings: List[Dict[str, Any]],
        source_version: int
    ) -> Dict[str, Any]:
        """Produces realistic, deterministic advisory responses for unit tests."""
        findings = list(base_findings)

        # Detect sample patterns for mock tests
        if "let total" in source_code or "मानो total" in source_code or "అనుకో total" in source_code:
            findings.append({
                "category": "quality",
                "severity": "info",
                "line": 1,
                "location": "Line 1",
                "title": "Variable Declaration Best Practice",
                "explanation": "Variable 'total' is clearly initialized. Using descriptive variable names improves maintainability.",
                "suggested_code": "// Good descriptive naming",
                "why": "Clear variable naming aids multilingual code readability.",
                "is_compiler_diagnostic": False,
                "confidence": "high"
            })

        summary = f"Mock AI Analysis complete. Identified {len(findings)} finding(s)."
        return {
            "success": True,
            "provider": "mock",
            "configured": True,
            "source_version": source_version,
            "analysis_summary": summary,
            "findings": findings,
            "pedagogical_note": "VITAL compiles multilingual scripts into standard IR. Keep blocks balanced.",
            "disclaimer": "AI suggestions are advisory. Your code is never modified automatically."
        }

    def _extract_compiler_findings(self, diagnostics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Converts raw compiler errors into structured findings."""
        findings = []
        status = diagnostics.get("execution_status")
        error_details = diagnostics.get("error_details") or {}
        raw_errors = error_details.get("errors") or []
        parser_log = diagnostics.get("parser_log", "")

        if status == "syntax_error":
            # If errors array is available from parser log
            if raw_errors:
                for err in raw_errors:
                    msg = err.get("message", "")
                    line = err.get("line")
                    title = "Confirmed Parser Syntax Error"
                    if "unbalanced brackets" in msg.lower():
                        title = "Compiler Error: Unbalanced Braces '{' or '}'"
                    elif "unbalanced parentheses" in msg.lower():
                        title = "Compiler Error: Unbalanced Parentheses '(' or ')'"
                    elif "logic error" in msg.lower() or "syntax" in msg.lower():
                        title = f"Compiler Syntax Error{f' at line {line}' if line else ''}"

                    findings.append({
                        "category": "compiler_error",
                        "severity": "error",
                        "line": line,
                        "location": f"Line {line}" if line else "Parser Stage",
                        "title": title,
                        "message": msg,
                        "explanation": f"Compiler syntax check failed: {msg}",
                        "suggestion": "Check statement syntax, operators, and delimiter matching.",
                        "suggested_code": "// Review statement syntax and balance delimiters",
                        "why": "The compiler parser stage requires valid block structure before IR generation.",
                        "is_compiler_diagnostic": True,
                        "confidence": "high"
                    })
            else:
                line = error_details.get("line")
                findings.append({
                    "category": "compiler_error",
                    "severity": "error",
                    "line": line,
                    "location": f"Line {line}" if line else "Parser Stage",
                    "title": "Confirmed Parser Syntax Error",
                    "message": parser_log.strip(),
                    "explanation": f"The VITAL compiler rejected the syntax: {parser_log.strip()}",
                    "suggestion": "Review delimiter balance and statement grammar.",
                    "suggested_code": "// Review delimiter balance and statement grammar",
                    "why": "The compiler parser stage requires valid block structure before IR generation.",
                    "is_compiler_diagnostic": True,
                    "confidence": "high"
                })

        elif status == "runtime_error":
            output = diagnostics.get("output", "")
            msg = output.strip() or error_details.get("message", "Runtime execution error")
            line = error_details.get("line")
            m = re.search(r'line\s+(\d+)', msg, re.IGNORECASE)
            if m:
                line = int(m.group(1))
            findings.append({
                "category": "compiler_error",
                "severity": "error",
                "line": line,
                "location": f"Line {line}" if line else "Runtime Execution",
                "title": "Confirmed Runtime Execution Error",
                "message": msg,
                "explanation": f"Execution halted due to runtime exception: {msg}",
                "suggestion": "Check variable values, operations, and execution bounds.",
                "suggested_code": "// Guard against runtime errors (e.g., zero denominators, undefined variables)",
                "why": "Runtime operations such as division by zero or invalid operations trigger exceptions during execution.",
                "is_compiler_diagnostic": True,
                "confidence": "high"
            })

        elif status == "timeout":
            findings.append({
                "category": "compiler_error",
                "severity": "error",
                "line": None,
                "location": "Runtime Timeout",
                "title": "Execution Timeout Limit Exceeded",
                "message": "Execution exceeded time limit",
                "explanation": "Program execution exceeded the safety timeout limit. Check for infinite loops or unbounded recursion.",
                "suggestion": "Ensure while loops have an update condition that eventually becomes false.",
                "suggested_code": "// Add loop counter increment or termination condition",
                "why": "Infinite loops consume resources indefinitely and are halted by the execution sandbox.",
                "is_compiler_diagnostic": True,
                "confidence": "high"
            })

        return findings

    def _merge_findings(
        self,
        base_findings: List[Dict[str, Any]],
        incoming_findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Merges findings and deduplicates intelligently without discarding distinct errors.
        - Delimiter issues confirmed by compiler upgrade local findings with compiler badge.
        - Generic duplicate compiler findings without line numbers are consolidated.
        - Findings with different lines, categories, or titles are strictly preserved.
        """
        merged = []
        seen = set()

        # Check compiler confirmations in incoming or base findings
        comp_has_bracket_error = any(
            f.get("is_compiler_diagnostic") and ("bracket" in f.get("title", "").lower() or "brace" in f.get("title", "").lower())
            for f in (base_findings + incoming_findings)
        )
        comp_has_paren_error = any(
            f.get("is_compiler_diagnostic") and "paren" in f.get("title", "").lower()
            for f in (base_findings + incoming_findings)
        )

        all_candidates = list(base_findings) + list(incoming_findings)

        # First pass: if local delimiter findings exist, upgrade them if compiler confirmed
        for f in all_candidates:
            title_lower = f.get("title", "").lower()
            is_comp = f.get("is_compiler_diagnostic", False)

            if not is_comp:
                if ("brace" in title_lower or "bracket" in title_lower) and comp_has_bracket_error:
                    f["is_compiler_diagnostic"] = True
                elif "parenthes" in title_lower and comp_has_paren_error:
                    f["is_compiler_diagnostic"] = True

        for f in all_candidates:
            title_lower = f.get("title", "").lower()
            is_comp = f.get("is_compiler_diagnostic", False)
            line = f.get("line")

            # Avoid adding duplicate generic compiler card if a specific line-numbered local finding exists
            if is_comp and line is None:
                if "parenthes" in title_lower and any("parenthes" in x.get("title", "").lower() and x.get("line") is not None for x in all_candidates):
                    continue
                if ("brace" in title_lower or "bracket" in title_lower) and any(("brace" in x.get("title", "").lower() or "bracket" in x.get("title", "").lower()) and x.get("line") is not None for x in all_candidates):
                    continue

            # Normalized deduplication key: line and issue identifier
            key_kw = title_lower.split(":")[0].strip() if ":" in title_lower else title_lower
            if "undefined variable" in title_lower:
                m = re.search(r"['\"](\w+)['\"]", title_lower)
                var = m.group(1) if m else title_lower
                dedup_key = (line, "undefined_var", var)
            elif "parenthes" in title_lower:
                dedup_key = (line, "paren")
            elif "brace" in title_lower or "bracket" in title_lower:
                dedup_key = (line, "brace")
            elif "consecutive operators" in title_lower:
                dedup_key = (line, "consec_ops")
            elif "division by zero" in title_lower:
                dedup_key = (line, "div_zero")
            else:
                dedup_key = (line, f.get("category"), key_kw)

            if dedup_key not in seen:
                seen.add(dedup_key)
                merged.append(f)

        return merged


# Singleton instance for app reuse
ai_assistant = VitalAIAssistant()
