# -*- coding: utf-8 -*-
"""
web/compiler_runner.py — Safe Backend Runner for the VITAL Compiler

This module connects the web API to the existing VITAL compiler without
modifying compiler behavior. It invokes the existing Compiler pipeline:
  1. app.run_lexer(source_code)  -> writes tests/lexer_log.txt & token stream
  2. app.run_parser(source_code) -> writes tests/parser_log.txt & ast_log.txt
  3. app.transpile(source_code)  -> generates IR
  4. app.execute(py_code)        -> writes tests/ir.txt, output.txt, symbol_table.txt

Security & Stability:
  - Subprocess execution isolation prevents memory leaks or server crashes.
  - Strict timeout (default 5 seconds) terminates infinite while loops cleanly.
  - UTF-8 stdin/stdout/stderr reconfiguration ensuring flawless multilingual scripts.
"""

import os
import sys
import time
import json
import subprocess
from typing import Dict, Any, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(PROJECT_ROOT, 'src')
TESTS_DIR = os.path.join(PROJECT_ROOT, 'tests')

# Runner child script executed in a separate process for isolation and timeout protection
SUBPROCESS_WORKER_SCRIPT = """# -*- coding: utf-8 -*-
import sys
import os
import io

# Crucial Windows fix: ensure stdin, stdout, and stderr are fully UTF-8 configured
if hasattr(sys.stdin, 'reconfigure'):
    sys.stdin.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

project_root = {project_root!r}
src_dir = os.path.join(project_root, 'src')
sys.path.insert(0, src_dir)

from main import Compiler, RULES_FILE

def main():
    source_code = sys.stdin.read()
    
    app = Compiler(RULES_FILE)
    app.load_rules()
    
    # 1. Lexical Analysis
    app.run_lexer(source_code)
    
    # 2. Parser Validation
    is_valid = app.run_parser(source_code)
    
    if not is_valid:
        sys.exit(2)  # Parser/Syntax error
        
    # 3. Transpilation & Execution
    py_code = app.transpile(source_code)
    app.execute(py_code)
    
    sys.exit(0)

if __name__ == '__main__':
    main()
"""


def _read_file_safe(filepath: str) -> str:
    """Reads a file if it exists, returning empty string otherwise."""
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                return f.read()
        except Exception as e:
            return f"[Error reading {os.path.basename(filepath)}: {e}]"
    return ""


def run_pipeline(source_code: str, timeout_seconds: float = 5.0) -> Dict[str, Any]:
    """
    Executes the VITAL compiler pipeline with the provided source code.
    
    Returns a dictionary containing:
      - success: bool
      - execution_status: str ("completed", "syntax_error", "timeout", "runtime_error", "empty")
      - status_message: str
      - elapsed_ms: float
      - output: str (content of output.txt)
      - lexer_log: str (content of lexer_log.txt)
      - parser_log: str (content of parser_log.txt)
      - ast_log: str (content of ast_log.txt)
      - ir_code: str (content of ir.txt)
      - symbol_table: str (content of symbol_table.txt)
      - error_details: Optional[Dict[str, Any]] with line numbers if available
    """
    if not source_code or not source_code.strip():
        return {
            "success": False,
            "execution_status": "empty",
            "status_message": "Error: No source code provided.",
            "elapsed_ms": 0.0,
            "output": "> Error: Empty source code. Please enter or select a VITAL program.\n",
            "lexer_log": "",
            "parser_log": "[ERROR] Source code is empty.",
            "ast_log": "",
            "ir_code": "",
            "symbol_table": "",
            "error_details": {"message": "Empty source code"}
        }

    # Ensure tests directory exists
    os.makedirs(TESTS_DIR, exist_ok=True)

    worker_code = SUBPROCESS_WORKER_SCRIPT.format(project_root=PROJECT_ROOT)
    
    # Environment with UTF-8 encoding forced
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"

    start_time = time.time()
    timed_out = False
    return_code = 0
    proc_stdout = ""
    proc_stderr = ""

    try:
        proc = subprocess.run(
            [sys.executable, "-c", worker_code],
            input=source_code,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            encoding='utf-8',
            cwd=SRC_DIR,
            env=env
        )
        return_code = proc.returncode
        proc_stdout = proc.stdout or ""
        proc_stderr = proc.stderr or ""
    except subprocess.TimeoutExpired as e:
        timed_out = True
        proc_stdout = e.stdout or "" if hasattr(e, 'stdout') else ""
        proc_stderr = e.stderr or "" if hasattr(e, 'stderr') else ""
    except Exception as e:
        return_code = -1
        proc_stderr = str(e)

    elapsed_ms = round((time.time() - start_time) * 1000, 2)

    # Read artifacts generated by the compiler in tests/
    output_txt = _read_file_safe(os.path.join(TESTS_DIR, "output.txt"))
    lexer_log = _read_file_safe(os.path.join(TESTS_DIR, "lexer_log.txt"))
    parser_log = _read_file_safe(os.path.join(TESTS_DIR, "parser_log.txt"))
    ast_log = _read_file_safe(os.path.join(TESTS_DIR, "ast_log.txt"))
    ir_txt = _read_file_safe(os.path.join(TESTS_DIR, "ir.txt"))
    symbol_table = _read_file_safe(os.path.join(TESTS_DIR, "symbol_table.txt"))

    # Determine execution status and parse error details
    error_details = None
    if timed_out:
        success = False
        execution_status = "timeout"
        status_message = f"Execution timed out ({timeout_seconds}s limit). Check for infinite loops."
        output_txt = f"[TIMEOUT ERROR]\nProgram execution exceeded maximum time limit of {timeout_seconds} seconds.\nPossible infinite while-loop or recursion detected.\n"
        error_details = {
            "type": "timeout",
            "message": f"Execution exceeded {timeout_seconds}s timeout",
            "line": None,
            "errors": [{
                "type": "timeout",
                "message": f"Execution exceeded {timeout_seconds}s timeout",
                "line": None
            }]
        }
    elif return_code == 2:
        # Parser validation failed
        success = False
        execution_status = "syntax_error"
        status_message = "Parser Error Detected: Structural or syntax validation failed"
        
        # Extract all distinct errors from parser log
        parsed_errors = []
        for line in parser_log.splitlines():
            line_str = line.strip()
            if line_str.startswith("[ERROR]"):
                msg = line_str[len("[ERROR]"):].strip()
                err_line = None
                import re
                m = re.search(r'line\s+(\d+)', line_str, re.IGNORECASE)
                if m:
                    err_line = int(m.group(1))
                parsed_errors.append({
                    "type": "syntax_error",
                    "message": msg,
                    "line": err_line
                })

        line_num = parsed_errors[0]["line"] if (parsed_errors and parsed_errors[0].get("line")) else None
        if not parsed_errors:
            for line in parser_log.splitlines():
                if "line" in line.lower():
                    import re
                    m = re.search(r'line\s+(\d+)', line, re.IGNORECASE)
                    if m:
                        line_num = int(m.group(1))
                        break
            parsed_errors = [{
                "type": "syntax_error",
                "message": parser_log.strip(),
                "line": line_num
            }]

        error_details = {
            "type": "syntax_error",
            "message": parser_log.strip(),
            "line": line_num,
            "errors": parsed_errors
        }
        if not output_txt or "RUNTIME ERROR" not in output_txt:
            output_txt = f"[CRITICAL] Compilation stopped due to structural/syntax errors.\nSee PARSER tab for diagnostics.\n"
    elif return_code != 0:
        # Runtime crash or system error
        success = False
        execution_status = "runtime_error"
        status_message = "Runtime Execution Error"
        err_msg = (proc_stderr or output_txt).strip()
        error_details = {
            "type": "runtime_error",
            "message": err_msg,
            "line": None,
            "errors": [{
                "type": "runtime_error",
                "message": err_msg,
                "line": None
            }]
        }
    else:
        # Check if output contains a runtime error logged by Compiler.execute()
        if "--- RUNTIME ERROR ---" in output_txt:
            success = False
            execution_status = "runtime_error"
            status_message = "Runtime Exception Detected during execution"
            err_msg = output_txt.strip()
            error_details = {
                "type": "runtime_error",
                "message": err_msg,
                "line": None,
                "errors": [{
                    "type": "runtime_error",
                    "message": err_msg,
                    "line": None
                }]
            }
        else:
            success = True
            execution_status = "completed"
            status_message = "Compilation Successful | IR Generated | Execution Complete"

    # Aggregated pipeline log matching gui.py view
    pipeline_summary = [
        f"═" * 60,
        f" VITAL MULTILINGUAL COMPILER PIPELINE RESULTS",
        f" Status: {status_message}",
        f" Pipeline Elapsed Time: {elapsed_ms} ms",
        f"═" * 60,
        "",
        "★ PROGRAM EXECUTION OUTPUT ★",
        "-" * 60,
        output_txt.strip() if output_txt.strip() else "(No standard output produced)",
        "",
        "1. LEXICAL ANALYSIS",
        "-" * 60,
        lexer_log.strip() if lexer_log.strip() else "(No lexer log)",
        "",
        "2. PARSER VALIDATION",
        "-" * 60,
        parser_log.strip() if parser_log.strip() else "(No parser log)",
        "",
        "3. ABSTRACT SYNTAX TREE",
        "-" * 60,
        ast_log.strip() if ast_log.strip() else "(No AST generated)",
        "",
        "4. TRANSPILED IR (PYTHON)",
        "-" * 60,
        ir_txt.strip() if ir_txt.strip() else "(No IR generated)",
        "",
        "5. SEMANTIC SYMBOL TABLE",
        "-" * 60,
        symbol_table.strip() if symbol_table.strip() else "(No symbol table generated)"
    ]
    aggregated_log = "\n".join(pipeline_summary)

    return {
        "success": success,
        "execution_status": execution_status,
        "status_message": status_message,
        "elapsed_ms": elapsed_ms,
        "output": output_txt,
        "lexer_log": lexer_log,
        "parser_log": parser_log,
        "ast_log": ast_log,
        "ir_code": ir_txt,
        "symbol_table": symbol_table,
        "aggregated_log": aggregated_log,
        "error_details": error_details,
        "compiler_stdout": proc_stdout,
        "compiler_stderr": proc_stderr
    }
