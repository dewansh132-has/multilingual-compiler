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
import tempfile
import shutil
from typing import Dict, Any, Optional

try:
    from sandbox_policy import get_sanitized_sandbox_env
except ImportError:
    from src.sandbox_policy import get_sanitized_sandbox_env

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
    
    # Check if execution recorded an unhandled exception
    res_path = os.path.join(project_root, 'tests', 'execution_result.json')
    if os.path.exists(res_path):
        try:
            import json
            with open(res_path, 'r', encoding='utf-8') as f:
                res = json.load(f)
            if not res.get('success'):
                sys.exit(1)
        except Exception:
            pass

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


def run_pipeline(source_code: str, timeout_seconds: float = 5.0, tracker: Optional[Any] = None) -> Dict[str, Any]:
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
    
    # Minimal sanitized environment and isolated temporary working directory
    temp_sandbox_dir = tempfile.mkdtemp(prefix="vital_sandbox_")
    env = get_sanitized_sandbox_env(temp_sandbox_dir)

    start_time = time.time()
    timed_out = False
    return_code = 0
    proc_stdout = ""
    proc_stderr = ""

    proc = None
    try:
        proc = subprocess.Popen(
            [sys.executable, "-c", worker_code],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            cwd=temp_sandbox_dir,
            env=env
        )
        if tracker is not None:
            tracker.active_sandbox_proc = proc

        proc_stdout, proc_stderr = proc.communicate(input=source_code, timeout=timeout_seconds)
        return_code = proc.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        if proc:
            try:
                proc.kill()
                proc.wait(timeout=1.0)
            except Exception:
                pass
        proc_stdout = ""
        proc_stderr = f"Execution exceeded {timeout_seconds}s timeout"
    except Exception as e:
        if proc:
            try:
                proc.kill()
                proc.wait(timeout=1.0)
            except Exception:
                pass
        return_code = -1
        proc_stderr = str(e)
    finally:
        if tracker is not None:
            tracker.active_sandbox_proc = None
        shutil.rmtree(temp_sandbox_dir, ignore_errors=True)

    elapsed_ms = round((time.time() - start_time) * 1000, 2)

    # Read artifacts generated by the compiler in tests/
    output_txt = _read_file_safe(os.path.join(TESTS_DIR, "output.txt"))
    lexer_log = _read_file_safe(os.path.join(TESTS_DIR, "lexer_log.txt"))
    parser_log = _read_file_safe(os.path.join(TESTS_DIR, "parser_log.txt"))
    ast_log = _read_file_safe(os.path.join(TESTS_DIR, "ast_log.txt"))
    ir_txt = _read_file_safe(os.path.join(TESTS_DIR, "ir.txt"))
    symbol_table = _read_file_safe(os.path.join(TESTS_DIR, "symbol_table.txt"))

    exec_meta_file = os.path.join(TESTS_DIR, "execution_result.json")
    exec_meta = {}
    if os.path.exists(exec_meta_file):
        try:
            with open(exec_meta_file, "r", encoding="utf-8") as f:
                exec_meta = json.load(f)
        except Exception:
            exec_meta = {}

    # Determine execution status and parse error details
    error_details = None
    exception_type = None
    exception_message = None
    traceback_frames = []
    traceback_str = ""
    killed_by = "none"
    exit_code = return_code

    if timed_out:
        success = False
        execution_status = "timeout"
        status_message = f"Execution timed out ({timeout_seconds}s limit). Check for infinite loops."
        output_txt = f"[TIMEOUT ERROR]\nProgram execution exceeded maximum time limit of {timeout_seconds} seconds.\nPossible infinite while-loop or recursion detected.\n"
        exit_code = -1
        killed_by = "timeout"
        exception_type = "TimeoutError"
        exception_message = f"Execution exceeded {timeout_seconds}s timeout"
        traceback_str = f"TimeoutError: Execution exceeded {timeout_seconds}s timeout"
        error_details = {
            "type": "timeout",
            "message": exception_message,
            "line": None,
            "errors": [{
                "type": "timeout",
                "message": exception_message,
                "line": None
            }]
        }
    elif return_code == 2:
        # Parser validation failed
        success = False
        execution_status = "syntax_error"
        status_message = "Parser Error Detected: Structural or syntax validation failed"
        exit_code = 2
        killed_by = "none"
        exception_type = "SyntaxError"
        exception_message = status_message
        traceback_str = parser_log
        
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
        exit_code = return_code
        err_msg = (proc_stderr or output_txt).strip()

        if exec_meta:
            exception_type = exec_meta.get("exception_type")
            exception_message = exec_meta.get("exception_message")
            traceback_frames = exec_meta.get("traceback_frames", [])
            traceback_str = exec_meta.get("traceback_str", "")
            killed_by = exec_meta.get("killed_by", "none")

        if not exception_type:
            import re
            m_type = re.search(r'Exception Type:\s*([A-Za-z0-9_]+)', output_txt)
            m_err = re.search(r'Execution Error:\s*(.*)', output_txt)
            if m_type:
                exception_type = m_type.group(1)
            if m_err:
                exception_message = m_err.group(1).strip()
            if not exception_type:
                m_direct = re.search(r'([A-Za-z0-9_]+Error):\s*(.*)', err_msg)
                if m_direct:
                    exception_type = m_direct.group(1)
                    exception_message = m_direct.group(2).strip()
                else:
                    exception_type = "RuntimeError"
                    exception_message = err_msg
            if not traceback_str:
                traceback_str = output_txt or proc_stderr

        if exception_type == "MemoryError":
            killed_by = "memory"

        error_details = {
            "type": "runtime_error",
            "message": exception_message or err_msg,
            "line": None,
            "errors": [{
                "type": "runtime_error",
                "message": exception_message or err_msg,
                "line": None
            }]
        }
    else:
        # Check if output contains a runtime error logged by Compiler.execute()
        if "--- RUNTIME ERROR ---" in output_txt:
            success = False
            execution_status = "runtime_error"
            status_message = "Runtime Exception Detected during execution"
            exit_code = 1
            err_msg = output_txt.strip()

            if exec_meta:
                exception_type = exec_meta.get("exception_type")
                exception_message = exec_meta.get("exception_message")
                traceback_frames = exec_meta.get("traceback_frames", [])
                traceback_str = exec_meta.get("traceback_str", "")
                killed_by = exec_meta.get("killed_by", "none")

            if not exception_type:
                import re
                m_type = re.search(r'Exception Type:\s*([A-Za-z0-9_]+)', output_txt)
                m_err = re.search(r'Execution Error:\s*(.*)', output_txt)
                if m_type:
                    exception_type = m_type.group(1)
                if m_err:
                    exception_message = m_err.group(1).strip()
                if not exception_type:
                    m_direct = re.search(r'([A-Za-z0-9_]+Error):\s*(.*)', err_msg)
                    if m_direct:
                        exception_type = m_direct.group(1)
                        exception_message = m_direct.group(2).strip()
                    else:
                        exception_type = "RuntimeError"
                        exception_message = err_msg
                if not traceback_str:
                    traceback_str = output_txt

            if exception_type == "MemoryError":
                killed_by = "memory"

            error_details = {
                "type": "runtime_error",
                "message": exception_message or err_msg,
                "line": None,
                "errors": [{
                    "type": "runtime_error",
                    "message": exception_message or err_msg,
                    "line": None
                }]
            }
        else:
            success = True
            execution_status = "completed"
            status_message = "Compilation Successful | IR Generated | Execution Complete"
            exit_code = 0
            killed_by = "none"

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
        "stdout": (output_txt or proc_stdout)[:4000],
        "stderr": proc_stderr[:4000],
        "exit_code": exit_code,
        "timed_out": timed_out,
        "killed_by": killed_by,
        "exception_type": exception_type,
        "exception_message": exception_message,
        "traceback_frames": traceback_frames,
        "traceback_str": traceback_str,
        "lexer_log": lexer_log,
        "parser_log": parser_log,
        "ast_log": ast_log,
        "ir_code": ir_txt,
        "symbol_table": symbol_table,
        "aggregated_log": aggregated_log,
        "error_details": error_details,
        "compiler_stdout": proc_stdout,
        "compiler_stderr": proc_stderr,
        "policy_violations": exec_meta.get("policy_violations", [])
    }
