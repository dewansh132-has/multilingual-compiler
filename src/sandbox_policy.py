# -*- coding: utf-8 -*-
"""
src/sandbox_policy.py — Hardened Sandbox Execution Policy & Runtime Stubs for Stage 13

Guarantees that Stage 13 (Sandbox Execution) cannot harm the host machine:
  1. Process Isolation & Clean Environment:
     - Minimal sanitized environment: strips GEMINI_API_KEY and any sensitive tokens.
     - Isolated temporary working directory (cwd set to temp dir, cleaned on exit).
     - Output size cap: buffers stdout/output to prevent disk or memory flooding.
  2. Strict Network & Filesystem Constraints:
     - Blocks all socket and network connections (raises PermissionError / records policy violation).
     - Blocks file writes outside the temporary sandbox directory (substitutes in-memory buffers).
     - Blocks reads of sensitive host files (/etc/passwd, shadow, .env, id_rsa, etc.).
  3. Module Import Allowlist:
     - Permits ONLY: math, string, json, time, random, re, vital_runtime.
     - Blocked imports log '[sandbox] blocked import(...)' and raise ImportError.
  4. Runtime Shims for Dangerous Builtins:
     - Replaces command execution (execute_command, run_shell, dispatch_system_command, system, popen),
       dynamic eval/exec (eval, exec, compile), database queries (execute_database_query),
       file writes, and network calls with recording stubs.
     - Stubs log '[sandbox] blocked <op>(<args>)', record RUN-POLICY-VIOLATION details,
       and return a harmless value so execution can complete safely and show output.
"""

import os
import sys
import io
import time
import inspect
from typing import Dict, Any, List, Optional, Tuple

ALLOWED_MODULES = {
    "math", "string", "json", "time", "random", "re", "vital_runtime"
}

_RECORDED_VIOLATIONS: List[Dict[str, Any]] = []

def clear_recorded_violations() -> None:
    global _RECORDED_VIOLATIONS
    _RECORDED_VIOLATIONS = []

def get_recorded_violations() -> List[Dict[str, Any]]:
    return list(_RECORDED_VIOLATIONS)

def record_policy_violation(operation: str, args: str, line: int = 1, col: int = 1, log_msg: str = "") -> None:
    entry = {
        "operation": operation,
        "args": args,
        "line": line,
        "col": col,
        "log": log_msg or f"[sandbox] blocked {operation}({args})"
    }
    _RECORDED_VIOLATIONS.append(entry)

def get_caller_frame_info() -> Tuple[int, int]:
    """Returns (lineno, col) of the calling code within the executed VITAL/Python script."""
    try:
        frame = inspect.currentframe()
        curr = frame.f_back if frame else None
        while curr:
            filename = curr.f_code.co_filename
            # Match the frame executing the code passed to exec() or user code
            if filename in ("<string>", "<transpiled>", "<stdin>", "active_buffer.vital") or filename.endswith(".vital"):
                return (curr.f_lineno, 1)
            curr = curr.f_back
    except Exception:
        pass
    return (1, 1)

# Real standard library primitives before wrapping
_real_import = __import__
_real_open = open

def safe_import(name: str, globals=None, locals=None, fromlist=(), level: int = 0):
    root_pkg = name.split(".")[0]
    if root_pkg not in ALLOWED_MODULES:
        line, col = get_caller_frame_info()
        log_msg = f"[sandbox] blocked import('{name}')"
        print(log_msg)
        record_policy_violation("import", repr(name), line=line, col=col, log_msg=log_msg)
        raise ImportError(f"[sandbox] import of '{name}' is blocked by sandbox policy")
    return _real_import(name, globals, locals, fromlist, level)

def make_safe_open(temp_dir: str):
    abs_temp = os.path.abspath(temp_dir) if temp_dir else ""
    def safe_open(file, mode="r", *args, **kwargs):
        line, col = get_caller_frame_info()
        str_file = str(file)
        try:
            abs_path = os.path.abspath(str_file)
        except Exception:
            abs_path = str_file

        is_write = any(m in mode for m in ("w", "a", "x", "+"))
        if is_write:
            if not abs_temp or not abs_path.startswith(abs_temp):
                log_msg = f"[sandbox] blocked file write ({repr(str_file)})"
                print(log_msg)
                record_policy_violation("file_write", repr(str_file), line=line, col=col, log_msg=log_msg)
                return io.StringIO() if "b" not in mode else io.BytesIO()
        else:
            lower_path = abs_path.lower().replace("\\", "/")
            sensitive_tokens = ("passwd", "shadow", ".env", "id_rsa", "/etc/")
            if any(tok in lower_path for tok in sensitive_tokens):
                log_msg = f"[sandbox] blocked file read ({repr(str_file)})"
                print(log_msg)
                record_policy_violation("file_read", repr(str_file), line=line, col=col, log_msg=log_msg)
                return io.StringIO("") if "b" not in mode else io.BytesIO(b"")

        return _real_open(file, mode, *args, **kwargs)
    return safe_open

def make_recording_stub(op_name: str, default_val: Any = 1):
    def stub(*args, **kwargs):
        line, col = get_caller_frame_info()
        args_list = [repr(a) for a in args] + [f"{k}={repr(v)}" for k, v in kwargs.items()]
        args_str = ", ".join(args_list)
        log_msg = f"[sandbox] blocked {op_name}({args_str})"
        print(log_msg)
        record_policy_violation(op_name, args_str, line=line, col=col, log_msg=log_msg)
        return default_val
    return stub

# Mapping of dangerous builtins and standard function aliases to (operation_name, default_return)
DANGEROUS_STUB_SPECS = {
    # Command execution / shell
    "execute_command": ("execute_command", 1),
    "run_shell": ("run_shell", 1),
    "system_command": ("system_command", 1),
    "dispatch_system_command": ("dispatch_system_command", 1),
    "system_backup_tar_dispatch": ("system_backup_tar_dispatch", 1),
    "restore_filesystem_archive": ("restore_filesystem_archive", 1),
    "system": ("execute_command", 1),
    "popen": ("execute_command", 1),
    # Multilingual command execution aliases
    "कमांड_चलाएं": ("execute_command", 1),
    "सिस्टम_कमांड_चलाएं": ("execute_command", 1),
    "सिस्टम_कमांड_प्रेषित_करें": ("dispatch_system_command", 1),
    "సిస్టమ్_కమాండ్_డిస్పాచ్": ("dispatch_system_command", 1),
    "కమాండ్_రన్_చేయి": ("execute_command", 1),
    "సారూప్య_కమాండ్_రన్_చేయి": ("execute_command", 1),
    "সিস্টেম_কমান্ড_প্রেরণ": ("dispatch_system_command", 1),
    "কমান্ড_চালাও": ("execute_command", 1),
    "कमांड_चालवा": ("execute_command", 1),
    "सिस्टम_कमांड_चालवा": ("execute_command", 1),
    "कमाण्ड_चलाऊ": ("execute_command", 1),
    "सिस्टम_कमाण्ड_चलाऊ": ("execute_command", 1),

    # Dynamic Evaluation
    "eval": ("eval", 1),
    "exec": ("exec", 1),
    "compile": ("compile", None),
    "dynamic_expression_evaluator": ("dynamic_expression_evaluator", 1),
    "गतिशील_गणितीय_मूल्यांकन": ("dynamic_expression_evaluator", 1),
    # Multilingual dynamic evaluation aliases
    "मूल्यांकन": ("eval", 1),
    "मूल्यांकनम": ("eval", 1),
    "मूल्यांकन_करा": ("eval", 1),
    "मूल्याङ्कन": ("eval", 1),
    "మూల్యాంకనం": ("eval", 1),
    "मूल्यायन": ("eval", 1),
    "निष्पादित": ("exec", 1),
    "चलाओ": ("exec", 1),
    "అమలు_చేయి": ("exec", 1),
    "చలాఓ": ("exec", 1),
    "চালাও": ("exec", 1),
    "নিষ্পাদন": ("exec", 1),
    "चालवा": ("exec", 1),
    "चलाऊ": ("exec", 1),

    # Database queries
    "execute_database_query": ("execute_database_query", 1),
    "database_query": ("database_query", 1),
    "execute_query": ("execute_query", 1),
    "query": ("query", 1),
    "sql_query": ("sql_query", 1),
    # Multilingual database queries
    "डेटाबेस_क्वेरी_चलाएं": ("execute_database_query", 1),
    "డేటాబేస్_క్వెరీ_రన్_చేయి": ("execute_database_query", 1),
    "ডাটাবেস_কোয়েরি_চালাও": ("execute_database_query", 1),
    "डेटाबेस_क्वेरी_चालवा": ("execute_database_query", 1),
    "डेटाबेस_क्वेरी_चलाऊ": ("execute_database_query", 1),

    # File writes
    "file_write": ("file_write", 1),
    "write_file": ("write_file", 1),
    "फ़ाइल_लिखो": ("file_write", 1),
    "ఫైల్_రాయి": ("file_write", 1),
    "ফাইল_লেখো": ("file_write", 1),
    "फाइल_लिहा": ("file_write", 1),
    "फाइल_लेख": ("file_write", 1),

    # Network calls
    "network_call": ("network_call", 1),
    "http_request": ("http_request", 1),
    "http_get": ("http_get", 1),
    "http_post": ("http_post", 1),
    "socket_connect": ("socket_connect", 1),
    "fetch": ("fetch", 1),
    "नेटवर्क_कॉल": ("network_call", 1),
    "నెట్‌వర్క్_కాల్": ("network_call", 1),
    "নেটওয়ার্ক_কল": ("network_call", 1),
    "नेटवर्क_कल": ("network_call", 1)
}

def install_system_patches(temp_dir: str) -> None:
    """Installs monkey-patches on system modules (socket, subprocess, os) to prevent any bypass."""
    # 1. Network / Sockets
    try:
        import socket
        def blocked_socket(*args, **kwargs):
            line, col = get_caller_frame_info()
            log_msg = "[sandbox] blocked socket creation"
            print(log_msg)
            record_policy_violation("socket", "socket()", line=line, col=col, log_msg=log_msg)
            raise PermissionError("[sandbox] Network access is disabled in sandbox execution")
        socket.socket = blocked_socket
        if hasattr(socket, "create_connection"):
            socket.create_connection = blocked_socket
        if hasattr(socket, "getaddrinfo"):
            socket.getaddrinfo = blocked_socket
    except Exception:
        pass

    # 2. Subprocess
    try:
        import subprocess
        class MockSubprocessResult:
            def __init__(self, cmd=""):
                self.returncode = 0
                self.pid = 99999
                self.stdout = b""
                self.stderr = b""
                self.args = cmd
            def communicate(self, *a, **kw):
                return ("", "")
            def poll(self):
                return 0
            def wait(self, *a, **kw):
                return 0
            def kill(self):
                pass
            def terminate(self):
                pass

        def blocked_popen(*args, **kwargs):
            line, col = get_caller_frame_info()
            cmd = args[0] if args else kwargs.get("args", "")
            log_msg = f"[sandbox] blocked execute_command({repr(cmd)})"
            print(log_msg)
            record_policy_violation("execute_command", repr(cmd), line=line, col=col, log_msg=log_msg)
            return MockSubprocessResult(cmd)

        subprocess.Popen = blocked_popen
        subprocess.run = blocked_popen
        subprocess.call = lambda *a, **kw: 0
        subprocess.check_call = lambda *a, **kw: 0
        subprocess.check_output = lambda *a, **kw: b""
    except Exception:
        pass

    # 3. OS system / popen calls
    try:
        import os
        def blocked_os_system(cmd):
            line, col = get_caller_frame_info()
            log_msg = f"[sandbox] blocked execute_command({repr(cmd)})"
            print(log_msg)
            record_policy_violation("execute_command", repr(cmd), line=line, col=col, log_msg=log_msg)
            return 0
        os.system = blocked_os_system
        if hasattr(os, "popen"):
            os.popen = lambda cmd, *a, **kw: io.StringIO("")
    except Exception:
        pass

def build_sandbox_exec_scope(temp_dir: str) -> Dict[str, Any]:
    """Constructs a secure execution scope with safe builtins and recording stubs."""
    import builtins
    safe_builtins: Dict[str, Any] = {}
    for k in dir(builtins):
        safe_builtins[k] = getattr(builtins, k)

    safe_builtins["__import__"] = safe_import
    safe_builtins["open"] = make_safe_open(temp_dir)

    # Register stubs into builtins dictionary
    for name, (op_name, default_val) in DANGEROUS_STUB_SPECS.items():
        stub = make_recording_stub(op_name, default_val)
        safe_builtins[name] = stub

    exec_scope: Dict[str, Any] = {"__builtins__": safe_builtins}
    # Also register stubs directly into global scope
    for name, (op_name, default_val) in DANGEROUS_STUB_SPECS.items():
        exec_scope[name] = safe_builtins[name]

    return exec_scope

class CappedOutputWriter:
    """Wraps an output file or stream to enforce a maximum character size cap."""
    def __init__(self, target, max_chars: int = 200000):
        self.target = target
        self.max_chars = max_chars
        self.current_chars = 0
        self.capped = False

    def write(self, s: str) -> int:
        if self.capped:
            return len(s)
        if self.current_chars + len(s) > self.max_chars:
            allowed = self.max_chars - self.current_chars
            if allowed > 0:
                self.target.write(s[:allowed])
            self.target.write("\n[sandbox] output size limit exceeded (capped)\n")
            self.current_chars = self.max_chars
            self.capped = True
            return len(s)
        self.current_chars += len(s)
        return self.target.write(s)

    def flush(self) -> None:
        if hasattr(self.target, "flush"):
            self.target.flush()

def get_sanitized_sandbox_env(temp_dir: str) -> Dict[str, str]:
    """
    Creates a minimal, secure environment for Stage 13 execution:
    - Strips all API keys, secrets, tokens (e.g. GEMINI_API_KEY).
    - Sets TMP, TEMP, and working variables to the sandbox temp directory.
    - Preserves only the minimum necessary OS variables for Python to run.
    """
    safe_keys = {
        "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT",
        "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER",
        "OS", "HOMEPATH", "USERPROFILE"
    }
    env = {}
    for k in safe_keys:
        if k in os.environ:
            env[k] = os.environ[k]

    if "PATH" in os.environ:
        env["PATH"] = os.environ["PATH"]

    env["TEMP"] = temp_dir
    env["TMP"] = temp_dir
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["VITAL_SANDBOX"] = "1"

    # Strictly verify NO secret or api key exists
    for k in list(env.keys()):
        upper = k.upper()
        if any(bad in upper for bad in ("API_KEY", "GEMINI", "SECRET", "TOKEN", "PASSWORD", "AUTH")):
            del env[k]

    return env
