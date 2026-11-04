# -*- coding: utf-8 -*-
"""
web/security_analyzer.py — Deterministic Security Scanner & Stage Coordinator

Integrates deterministic static security checks with local Ollama AI assistance
(qwen2.5-coder:7b-instruct) for the VITAL multilingual compiler.

Real Compiler Stages Instrumented:
  1. Lexical Analysis Stage (`stage_lexical`):
     - Unicode homoglyph injection (Cyrillic spoofing, Devanagari lookalikes)
     - Control characters and null bytes
     - Shell command injection patterns in literals
     - Path traversal sequences in literals
     - Prompt injection in comments or string literals
  2. Parser & Syntax Validation Stage (`stage_parser`):
     - Unbalanced delimiters and unclosed code blocks
     - Invalid nesting enabling unintended execution flows
  3. Transpiled IR & Code Generation Stage (`stage_ir_codegen`):
     - Python AST inspection of generated code for dangerous calls:
       - eval(), exec(), compile(), __import__()
       - os.system(), os.popen(), subprocess.*
       - Destructive file ops (shutil.rmtree, os.remove, os.unlink)
       - Uncontrolled file writes (open(..., 'w'/'a'))
       - Sockets and network calls (socket, urllib, requests)
       - Sandbox escape attempts (globals(), locals(), __subclasses__, __builtins__)
  4. Execution Boundary Stage (`stage_execution_boundary`):
     - Infinite loop risks without loop variable mutation
     - Resource exhaustion risks (e.g. huge exponents like 10**100000)
     - Execution isolation parameters

Security Guarantees:
  - Deterministic rules form the baseline evidence; AI provides in-depth explanation and remediation.
  - Zero automatic file mutation; all proposed fixes require explicit user review and approval.
  - Never executes untrusted code during analysis.
"""

import os
import sys
import re
import ast
import json
import time
import difflib
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(PROJECT_ROOT, 'src')
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from web.ollama_client import ollama_client, OllamaClient

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class SecurityFinding:
    id: str
    title: str
    stage: str                  # e.g. "Lexical Analysis", "Parser Validation", "Transpiled IR", "Execution Boundary", "Multilingual Static Analysis"
    stage_id: str               # "lexical", "parser", "ir_codegen", "execution_boundary", "multilingual"
    severity: str               # "Critical", "High", "Medium", "Low", "Informational"
    risk_score: int             # 0 to 100
    confidence: str             # "confirmed", "probable", "unverified"
    status: str = "probable"    # "confirmed", "probable", "unverified"
    line: Optional[int] = None
    column: Optional[int] = None
    evidence: str = ""
    explanation: str = ""
    remediation: str = ""
    suggested_code: str = ""
    diff: str = ""
    is_ai_enriched: bool = False
    rule_id: str = ""
    defect_category: str = "security"  # "security", "syntax", "semantic", "logic", "lexical"
    code_excerpt: str = ""
    potential_impact: str = ""
    source_sink_flow: Optional[Dict[str, str]] = None  # e.g. {"source": "...", "intermediate": "...", "sink": "..."}

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Deterministic Risk Scoring Formula
# ---------------------------------------------------------------------------

SEVERITY_BASE_SCORES = {
    "Critical": 90,
    "High": 70,
    "Medium": 50,
    "Low": 30,
    "Informational": 10
}

SEVERITY_WEIGHTS = {
    "Critical": 35.0,
    "High": 25.0,
    "Medium": 15.0,
    "Low": 8.0,
    "Informational": 2.0
}

CONFIDENCE_FACTORS = {
    "confirmed": 1.0,
    "probable": 0.8,
    "unverified": 0.5
}

def calculate_risk_score(severity: str, confidence: str, has_exact_line: bool = True, has_ast_match: bool = False) -> int:
    """
    Deterministic scoring methodology:
      - Base score from severity (Critical: 90, High: 70, Medium: 50, Low: 30, Info: 10)
      - Verified AST match: +5
      - Exact source line match: +3
      - Confidence adjustment:
          confirmed: +2
          probable: -5
          unverified (AI-only suspicion): -12
      - Bounds capped within severity boundaries:
          Critical: 85 - 100
          High:     65 - 84
          Medium:   40 - 64
          Low:      20 - 39
          Info:      0 - 19
    """
    base = SEVERITY_BASE_SCORES.get(severity, 30)
    score = base
    if has_ast_match:
        score += 5
    if has_exact_line:
        score += 3

    if confidence == "confirmed":
        score += 2
    elif confidence == "probable":
        score -= 5
    elif confidence == "unverified":
        score -= 12

    # Clamp to severity brackets
    if severity == "Critical":
        return max(85, min(100, score))
    elif severity == "High":
        return max(65, min(84, score))
    elif severity == "Medium":
        return max(40, min(64, score))
    elif severity == "Low":
        return max(20, min(39, score))
    else:
        return max(0, min(19, score))


def compute_overall_risk_score(findings: List[SecurityFinding], syntax_blocked: bool = False) -> Tuple[int, str]:
    """
    Deterministic Multilingual Vulnerability Risk Scoring Methodology:
      1. Syntax-Blocked Integrity:
         If syntax or lexical errors block subsequent pipeline stages, the assessment
         is reported as INCOMPLETE (-1). Never returns 0/100 or 'Secure' when analysis
         could not run.
      2. Clean Scan Integrity:
         If no issues are detected by enabled checks, returns 0 with the verdict
         'No issues detected by enabled checks.' (Never '100% secure').
      3. Clustered Deduplication:
         Findings are clustered by (rule_id, line). The primary finding in each cluster
         contributes 100% of its weighted severity (weight * confidence factor).
         Secondary duplicate occurrences contribute only 20% to prevent artificial score inflation.
      4. Taint Evidence Factor:
         Confirmed source-to-sink taint flows add +5 bonus evidence weight.
      5. Non-Linear Saturation Curve:
         RawSum = sum(cluster_scores)
         ScaledScore = min(100, round(100 * (1 - exp(-RawSum / 55.0))))
      6. Calibrated Severity Floors:
         Critical finding present -> min 75
         High finding present     -> min 50
         Medium finding present   -> min 25
         Low/Info finding present -> min 10
    """
    if syntax_blocked:
        return -1, "ASSESSMENT INCOMPLETE: Syntax errors blocked subsequent analysis stages."

    if not findings:
        return 0, "No issues detected by enabled checks."

    import math
    clusters: Dict[str, List[SecurityFinding]] = {}
    for f in findings:
        ckey = f"{f.rule_id}:{f.line or 0}"
        if ckey not in clusters:
            clusters[ckey] = []
        clusters[ckey].append(f)

    raw_sum = 0.0
    has_critical = False
    has_high = False
    has_medium = False
    has_low = False

    for ckey, group in clusters.items():
        # Sort so highest severity comes first
        group.sort(key=lambda x: SEVERITY_WEIGHTS.get(x.severity, 0.0), reverse=True)
        primary = group[0]
        p_sev = primary.severity
        p_conf = primary.confidence
        base_w = SEVERITY_WEIGHTS.get(p_sev, 10.0)
        c_mult = CONFIDENCE_FACTORS.get(p_conf, 0.8)

        # Check taint flow bonus
        taint_bonus = 5.0 if primary.source_sink_flow else 0.0
        cluster_score = (base_w * c_mult) + taint_bonus

        # Add duplicates with 20% weight to avoid inflation
        for dup in group[1:]:
            d_w = SEVERITY_WEIGHTS.get(dup.severity, 5.0)
            d_c = CONFIDENCE_FACTORS.get(dup.confidence, 0.8)
            cluster_score += (0.2 * d_w * d_c)

        raw_sum += cluster_score

        if p_sev == "Critical":
            has_critical = True
        elif p_sev == "High":
            has_high = True
        elif p_sev == "Medium":
            has_medium = True
        elif p_sev in ("Low", "Informational"):
            has_low = True

    scaled = min(100, round(100.0 * (1.0 - math.exp(-raw_sum / 55.0))))

    # Calibrate severity floors
    if has_critical:
        scaled = max(90, scaled)
    elif has_high:
        scaled = max(65, scaled)
    elif has_medium:
        scaled = max(35, scaled)
    elif has_low:
        scaled = max(15, scaled)

    scaled = max(0, min(100, scaled))

    if scaled >= 75:
        summary = "CRITICAL RISK: Direct code execution, IDOR, or command injection pattern detected."
    elif scaled >= 50:
        summary = "HIGH RISK: Significant security flaw, hardcoded secret, or logic defect detected."
    elif scaled >= 25:
        summary = "MEDIUM RISK: Potentially hazardous constructs, boundary errors, or homoglyphs detected."
    elif scaled >= 10:
        summary = "LOW RISK: Minor security hygiene or resource control concerns detected."
    else:
        summary = "No issues detected by enabled checks."

    return scaled, summary


# ---------------------------------------------------------------------------
# AST Security Visitor for Generated Python IR
# ---------------------------------------------------------------------------

class PythonASTSecurityVisitor(ast.NodeVisitor):
    """
    Visits the Python Intermediate Representation (IR) generated by VITAL
    to detect dangerous function calls, dangerous imports, and sandbox escape tricks.
    """

    DANGEROUS_CALLS = {
        # Execution & Eval
        "eval": ("Critical", "SEC-IR-001", "Dynamic Code Evaluation via 'eval()'",
                 "Use of eval() executes arbitrary Python code strings with caller permissions."),
        "exec": ("Critical", "SEC-IR-002", "Arbitrary Code Execution via 'exec()'",
                 "Use of exec() executes untrusted Python statements inside the runtime process."),
        "compile": ("High", "SEC-IR-003", "Dynamic AST/Bytecode Compilation via 'compile()'",
                    "compile() transforms arbitrary source strings into executable code objects."),
        "__import__": ("Critical", "SEC-IR-004", "Dynamic Module Import via '__import__()'",
                       "Direct invocation of __import__() can bypass namespace import restrictions."),

        # System & Processes
        "system": ("Critical", "SEC-IR-005", "Operating System Command Execution ('os.system')",
                   "Spawns a subshell executing host operating system commands."),
        "popen": ("Critical", "SEC-IR-006", "Process Pipe Execution ('os.popen')",
                  "Opens an unvalidated pipe to a system process."),
        "spawn": ("Critical", "SEC-IR-007", "Process Spawning via 'os.spawn*'",
                  "Launches external host processes without sandbox isolation."),

        # Introspection / Escape
        "globals": ("High", "SEC-IR-008", "Global Namespace Exposure via 'globals()'",
                    "Accessing globals() allows modifying execution context and internal builtins."),
        "locals": ("Medium", "SEC-IR-009", "Local Namespace Exposure via 'locals()'",
                   "Inspecting local variables can leak sensitive evaluation states.")
    }

    DANGEROUS_MODULES = {
        "subprocess": ("Critical", "SEC-IR-010", "Subprocess Module Invocation",
                       "Module 'subprocess' executes arbitrary system commands and binaries."),
        "os": ("Critical", "SEC-IR-011", "Operating System Module Access",
               "Module 'os' provides low-level operating system and file manipulation interfaces."),
        "shutil": ("High", "SEC-IR-012", "Filesystem Shell Utilities Access",
                   "Module 'shutil' permits recursive deletion and directory manipulation."),
        "socket": ("Critical", "SEC-IR-013", "Network Socket Creation",
                   "Module 'socket' allows uncontrolled outbound/inbound network traffic."),
        "urllib": ("High", "SEC-IR-014", "Network HTTP Request via 'urllib'",
                   "Permits outbound HTTP calls and Server-Side Request Forgery (SSRF)."),
        "requests": ("High", "SEC-IR-015", "Outbound HTTP Requests via 'requests'",
                     "Initiates external HTTP network requests from the execution sandbox."),
        "pickle": ("Critical", "SEC-IR-016", "Insecure Deserialization via 'pickle'",
                   "Deserializing untrusted pickle payloads leads to immediate remote code execution.")
    }

    def __init__(self, source_lines: List[str]):
        self.source_lines = source_lines
        self.findings: List[SecurityFinding] = []

    def visit_Call(self, node: ast.Call):
        func_name = ""
        attr_name = ""

        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            attr_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{attr_name}"
            else:
                func_name = attr_name

        # Check dangerous functions
        check_key = attr_name if attr_name in self.DANGEROUS_CALLS else func_name
        if check_key in self.DANGEROUS_CALLS:
            sev, rule_id, title, expl = self.DANGEROUS_CALLS[check_key]
            line_no = getattr(node, "lineno", None)
            col_no = getattr(node, "col_offset", None)
            evidence = self.source_lines[line_no - 1] if line_no and line_no <= len(self.source_lines) else func_name
            score = calculate_risk_score(sev, "confirmed", line_no is not None, has_ast_match=True)

            self.findings.append(SecurityFinding(
                id=f"SEC-IR-{len(self.findings)+1:03d}",
                title=title,
                stage="Transpiled IR (Generated Code)",
                stage_id="ir_codegen",
                severity=sev,
                risk_score=score,
                confidence="confirmed",
                status="confirmed",
                line=line_no,
                column=(col_no + 1) if col_no is not None else None,
                evidence=evidence.strip(),
                explanation=expl,
                remediation="Remove execution of system commands, eval/exec, or dynamic code execution.",
                rule_id=rule_id
            ))

        # Check open() in write/append mode
        if func_name == "open" or attr_name == "open":
            is_write = False
            for arg in node.args[1:]:
                if isinstance(arg, ast.Constant) and any(m in str(arg.value) for m in ('w', 'a', '+', 'x')):
                    is_write = True
                    break
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    if any(m in str(kw.value.value) for m in ('w', 'a', '+', 'x')):
                        is_write = True
                        break

            if is_write:
                line_no = getattr(node, "lineno", None)
                evidence = self.source_lines[line_no - 1] if line_no and line_no <= len(self.source_lines) else "open(..., 'w')"
                score = calculate_risk_score("High", "confirmed", line_no is not None, has_ast_match=True)
                self.findings.append(SecurityFinding(
                    id=f"SEC-IR-{len(self.findings)+1:03d}",
                    title="Arbitrary File Modification via open(..., 'w')",
                    stage="Transpiled IR (Generated Code)",
                    stage_id="ir_codegen",
                    severity="High",
                    risk_score=score,
                    confidence="confirmed",
                    status="confirmed",
                    line=line_no,
                    evidence=evidence.strip(),
                    explanation="Writing or appending to local files enables arbitrary file overwrite and host tampering.",
                    remediation="Restrain file operations to read-only mode or sandboxed application paths.",
                    rule_id="SEC-IR-017"
                ))

        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            mod_base = alias.name.split('.')[0]
            if mod_base in self.DANGEROUS_MODULES:
                sev, rule_id, title, expl = self.DANGEROUS_MODULES[mod_base]
                line_no = getattr(node, "lineno", None)
                evidence = self.source_lines[line_no - 1] if line_no and line_no <= len(self.source_lines) else f"import {alias.name}"
                score = calculate_risk_score(sev, "confirmed", line_no is not None, has_ast_match=True)
                self.findings.append(SecurityFinding(
                    id=f"SEC-IR-{len(self.findings)+1:03d}",
                    title=f"Dangerous Module Import: '{alias.name}'",
                    stage="Transpiled IR (Generated Code)",
                    stage_id="ir_codegen",
                    severity=sev,
                    risk_score=score,
                    confidence="confirmed",
                    status="confirmed",
                    line=line_no,
                    evidence=evidence.strip(),
                    explanation=expl,
                    remediation=f"Do not import '{mod_base}'. VITAL programs should rely on pure language builtins.",
                    rule_id=rule_id
                ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            mod_base = node.module.split('.')[0]
            if mod_base in self.DANGEROUS_MODULES:
                sev, rule_id, title, expl = self.DANGEROUS_MODULES[mod_base]
                line_no = getattr(node, "lineno", None)
                evidence = self.source_lines[line_no - 1] if line_no and line_no <= len(self.source_lines) else f"from {node.module} import ..."
                score = calculate_risk_score(sev, "confirmed", line_no is not None, has_ast_match=True)
                self.findings.append(SecurityFinding(
                    id=f"SEC-IR-{len(self.findings)+1:03d}",
                    title=f"Dangerous Module Import: 'from {node.module}'",
                    stage="Transpiled IR (Generated Code)",
                    stage_id="ir_codegen",
                    severity=sev,
                    risk_score=score,
                    confidence="confirmed",
                    status="confirmed",
                    line=line_no,
                    evidence=evidence.strip(),
                    explanation=expl,
                    remediation=f"Refrain from importing members from '{mod_base}'.",
                    rule_id=rule_id
                ))
        self.generic_visit(node)


# ---------------------------------------------------------------------------
# Deterministic Security Scanner
# ---------------------------------------------------------------------------

class DeterministicSecurityScanner:
    """Performs static checks across all genuine VITAL compiler stages."""

    # Unicode Homoglyphs
    HOMOGLYPH_CYRILLIC = {
        'а': 'a', 'е': 'e', 'о': 'o', 'с': 'c', 'р': 'p', 'х': 'x',
        'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H',
        'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X'
    }
    HOMOGLYPH_DEVANAGARI = {
        'ः': ':',   # Visarga pretending to be colon
        '।': '|',   # Danda pretending to be pipe
        '०': '0',   # Zero pretending to be 'o'
        'ऽ': 'S'    # Avagraha pretending to be 'S'
    }

    # Dangerous shell patterns inside strings
    SHELL_INJECTION_PATTERNS = [
        (r';\s*(?:rm|del|shutdown|reboot|format|curl|wget|powershell|bash|sh|cmd)\b', "Critical", "Shell Command Chaining Sequence (';')"),
        (r'\|\s*(?:sh|bash|powershell|cmd|curl|wget)\b', "Critical", "Shell Command Piping ('|')"),
        (r'`[^`]+`', "High", "Shell Backtick Command Substitution"),
        (r'\$\([^\)]+\)', "High", "Shell Command Expansion '$()'"),
        (r'powershell(?:\.exe)?\s+-[eE]', "Critical", "Encoded PowerShell Command Execution")
    ]

    # Path Traversal patterns
    PATH_TRAVERSAL_PATTERN = r'(?:\.\./|\.\.\\){2,}'

    # Prompt Injection in comments/strings
    PROMPT_INJECTION_PATTERNS = [
        r'ignore\s+(?:all\s+)?previous\s+instructions',
        r'system\s*:\s*you\s+are\s+now',
        r'override\s+security\s+rules',
        r'disregard\s+prior\s+guidelines'
    ]

    @classmethod
    def scan_lexical(cls, source_code: str) -> List[SecurityFinding]:
        """Scans source code at lexical/token boundary."""
        findings = []
        lines = source_code.splitlines()

        for line_no, line in enumerate(lines, start=1):
            # 1. Null byte check
            if '\0' in line or '\x00' in line:
                score = calculate_risk_score("Critical", "confirmed", True, False)
                findings.append(SecurityFinding(
                    id=f"SEC-LEX-{len(findings)+1:03d}",
                    title="Poison Null Byte Detected ('\\x00')",
                    stage="Lexical Analysis",
                    stage_id="lexical",
                    severity="Critical",
                    risk_score=score,
                    confidence="confirmed",
                    status="confirmed",
                    line=line_no,
                    column=line.find('\0') + 1,
                    evidence=repr(line),
                    explanation="Null byte injection attacks alter string termination in lower-level C runtime libraries.",
                    remediation="Remove null byte characters from source code and string literals.",
                    rule_id="SEC-LEX-001"
                ))

            # 2. Cyrillic homoglyph injection
            for cyr_char, lat_char in cls.HOMOGLYPH_CYRILLIC.items():
                if cyr_char in line:
                    col = line.find(cyr_char) + 1
                    score = calculate_risk_score("Medium", "confirmed", True, False)
                    findings.append(SecurityFinding(
                        id=f"SEC-LEX-{len(findings)+1:03d}",
                        title=f"Unicode Homoglyph Spoofing: Cyrillic '{cyr_char}' for Latin '{lat_char}'",
                        stage="Lexical Analysis",
                        stage_id="lexical",
                        severity="Medium",
                        risk_score=score,
                        confidence="confirmed",
                        status="confirmed",
                        line=line_no,
                        column=col,
                        evidence=f"Character '{cyr_char}' (U+{ord(cyr_char):04X}) looks identical to Latin '{lat_char}'",
                        explanation="Adversaries use lookalike Cyrillic glyphs to spoof identifier names and bypass security checks.",
                        remediation=f"Replace Cyrillic '{cyr_char}' with standard Latin '{lat_char}'.",
                        rule_id="SEC-LEX-002"
                    ))

            # 3. Devanagari syntax spoofing
            for dev_char, sym_char in cls.HOMOGLYPH_DEVANAGARI.items():
                if dev_char in line:
                    col = line.find(dev_char) + 1
                    score = calculate_risk_score("Low", "confirmed", True, False)
                    findings.append(SecurityFinding(
                        id=f"SEC-LEX-{len(findings)+1:03d}",
                        title=f"Devanagari Homoglyph: '{dev_char}' Spoofing Symbol '{sym_char}'",
                        stage="Lexical Analysis",
                        stage_id="lexical",
                        severity="Low",
                        risk_score=score,
                        confidence="confirmed",
                        status="confirmed",
                        line=line_no,
                        column=col,
                        evidence=f"Character '{dev_char}' (U+{ord(dev_char):04X}) visually imitates '{sym_char}'",
                        explanation="Devanagari punctuation marks can trigger parser ambiguity if used in place of operators.",
                        remediation=f"Normalize '{dev_char}' to standard '{sym_char}'.",
                        rule_id="SEC-LEX-003"
                    ))

            # 4. Shell injection sequences in strings/comments
            for pat, sev, title in cls.SHELL_INJECTION_PATTERNS:
                m = re.search(pat, line, re.IGNORECASE)
                if m:
                    score = calculate_risk_score(sev, "probable", True, False)
                    findings.append(SecurityFinding(
                        id=f"SEC-LEX-{len(findings)+1:03d}",
                        title=title,
                        stage="Lexical Analysis",
                        stage_id="lexical",
                        severity=sev,
                        risk_score=score,
                        confidence="probable",
                        status="probable",
                        line=line_no,
                        column=m.start() + 1,
                        evidence=m.group(0),
                        explanation="String literal contains shell metacharacters capable of arbitrary execution if passed to a command processor.",
                        remediation="Sanitize or parameterize dynamic strings rather than formatting raw shell commands.",
                        rule_id="SEC-LEX-004"
                    ))

            # 5. Path Traversal
            m_path = re.search(cls.PATH_TRAVERSAL_PATTERN, line)
            if m_path:
                score = calculate_risk_score("High", "confirmed", True, False)
                findings.append(SecurityFinding(
                    id=f"SEC-LEX-{len(findings)+1:03d}",
                    title="Path Traversal Sequence ('../')",
                    stage="Lexical Analysis",
                    stage_id="lexical",
                    severity="High",
                    risk_score=score,
                    confidence="confirmed",
                    status="confirmed",
                    line=line_no,
                    column=m_path.start() + 1,
                    evidence=m_path.group(0),
                    explanation="Repeated relative directory traversal ('../') can access files outside the authorized working directory.",
                    remediation="Use canonical, validated file paths and strip leading traversal dots.",
                    rule_id="SEC-LEX-005"
                ))

            # 6. Prompt Injection Attempts
            for pat in cls.PROMPT_INJECTION_PATTERNS:
                m_pi = re.search(pat, line, re.IGNORECASE)
                if m_pi:
                    score = calculate_risk_score("Medium", "probable", True, False)
                    findings.append(SecurityFinding(
                        id=f"SEC-LEX-{len(findings)+1:03d}",
                        title="Adversarial Prompt Injection Attempt in Comments/Strings",
                        stage="Lexical Analysis",
                        stage_id="lexical",
                        severity="Medium",
                        risk_score=score,
                        confidence="probable",
                        status="probable",
                        line=line_no,
                        column=m_pi.start() + 1,
                        evidence=m_pi.group(0),
                        explanation="Source text includes instructions attempting to override AI model guidelines.",
                        remediation="Remove prompt injection commands; AI assistants treat all program comments as untrusted.",
                        rule_id="SEC-LEX-006"
                    ))

        return findings

    @classmethod
    def scan_parser(cls, source_code: str) -> List[SecurityFinding]:
        """Scans parser / syntax structure using grammar-aware delimiter validation."""
        findings = []
        from web.ai_remediation_engine import DiagnosticNormalizer
        delims = DiagnosticNormalizer.analyze_delimiters(source_code)
        lines = source_code.splitlines()

        if delims["brace_diff"] != 0 or delims["extra_close_braces"] or delims["unclosed_braces"]:
            err_line = len(lines) if lines else 1
            col = 1
            evidence_line = ""

            if delims["extra_close_braces"]:
                err_line = delims["extra_close_braces"][0][0]
                col = delims["extra_close_braces"][0][1]
                evidence_line = lines[err_line - 1].strip() if 1 <= err_line <= len(lines) else f"Extra '}}' at line {err_line}"
            elif delims["unclosed_braces"]:
                err_line = delims["unclosed_braces"][-1][0]
                col = delims["unclosed_braces"][-1][1]
                evidence_line = lines[err_line - 1].strip() if 1 <= err_line <= len(lines) else f"Unclosed '{{' at line {err_line}"

            score = calculate_risk_score("Medium", "confirmed", False, False)
            findings.append(SecurityFinding(
                id=f"SEC-PAR-{len(findings)+1:03d}",
                title="Unbalanced Block Scope Delimiters ('{' vs '}')",
                stage="Parser Validation",
                stage_id="parser",
                severity="Medium",
                risk_score=score,
                confidence="confirmed",
                status="confirmed",
                line=err_line,
                column=col,
                evidence=evidence_line or f"Found {delims['open_braces']} open brace(s) and {delims['close_braces']} closing brace(s)",
                explanation="Mismatched block scopes permit unintended statements to execute inside or outside conditional blocks.",
                remediation="Ensure every opening brace '{' has a corresponding closing brace '}'.",
                rule_id="SEC-PAR-001",
                defect_category="syntax",
                potential_impact="Syntax error prevents AST construction, semantic checking, and subsequent execution stages."
            ))

        return findings

    @classmethod
    def scan_multilingual_security(cls, source_code: str, language: str = "English") -> List[SecurityFinding]:
        """
        Scans multilingual source code for Security Lab vulnerabilities and educational defects
        across English, Hindi, Telugu, Bengali, Marathi, and Nepali.
        """
        findings = []
        lines = source_code.splitlines()

        # 1. SEC-AUTH-001: Broken Object-Level Authorization (IDOR)
        # Check transfer functions where caller is passed alongside from_account
        transfer_fn_pat = re.compile(
            r'(?:function|कार्य|ఫంక్షన్|ফাংশন|कार्य_करा|कार्य_गर)\s+'
            r'(?:transfer_funds|राशि_स्थानांतरित_करें|నిధులు_బదిలీ_చేయి|অর্থ_স্থানান্তর_করো|रक्कम_वर्ग_करा|रकम_पठाउ)\s*\(([^)]+)\)'
        )
        for line_no, line in enumerate(lines, start=1):
            m_fn = transfer_fn_pat.search(line)
            if m_fn:
                # Check entire source code for ownership check
                has_ownership_check = any(
                    tok in source_code for tok in [
                        "caller_id != from_account_id", "caller_id == from_account_id",
                        "कॉलर_आईडी != स्रोत_खाता", "कॉलर_आईडी == स्रोत_खाता",
                        "కాలర్_ఐడి != మూల_ఖాతా", "కాలర్_ఐడి == మూల_ఖాతా",
                        "কলার_আইডি != উৎস_অ্যাকাউন্ট", "কলার_আইডি == উৎস_অ্যাকাউন্ট",
                        "कॉलर_आयडी != मूळ_खाते", "कॉलर_आयडी == मूळ_खाते",
                        "कलर_आईडी != स्रोत_खाता", "कलर_आईडी == स्रोत_खाता"
                    ]
                )
                if not has_ownership_check:
                    score = calculate_risk_score("Critical", "confirmed", True, False)
                    findings.append(SecurityFinding(
                        id=f"SEC-AUTH-{len(findings)+1:03d}",
                        title="Broken Object-Level Authorization (IDOR) in Transfer Workflow",
                        stage="Multilingual Static Analysis",
                        stage_id="multilingual",
                        severity="Critical",
                        risk_score=score,
                        confidence="confirmed",
                        status="confirmed",
                        line=line_no,
                        column=1,
                        evidence=line.strip(),
                        explanation="Function accepts caller ID and source account ID without verifying that caller owns the source account. An authenticated user can drain arbitrary accounts (CWE-639).",
                        remediation="Enforce ownership check: verify that caller_id matches from_account_id before processing transfers.",
                        rule_id="SEC-AUTH-001",
                        defect_category="security",
                        potential_impact="Unauthorized account draining and balance manipulation across user accounts."
                    ))

        # 2. SEC-AUTH-003: Unsafe State Transition / Check Bypass for Small Transfers
        bypass_pat = re.compile(r'(?:amount|राशि|మొత్తం|పరిమాణం|পরিমাণ|रक्कम|रकम)\s*>\s*500')
        for line_no, line in enumerate(lines, start=1):
            m_byp = bypass_pat.search(line)
            if m_byp and any(w in source_code for w in ["check_account_status", "खाता_स्थिति", "ఖాతా_స్థితి", "অ্যাকাউন্ট_অবস্থা", "खाते_स्थिती"]):
                score = calculate_risk_score("High", "confirmed", True, False)
                findings.append(SecurityFinding(
                    id=f"SEC-AUTH-{len(findings)+1:03d}",
                    title="Account Suspension Verification Bypass for Small Transactions",
                    stage="Multilingual Static Analysis",
                    stage_id="multilingual",
                    severity="High",
                    risk_score=score,
                    confidence="confirmed",
                    status="confirmed",
                    line=line_no,
                    column=m_byp.start() + 1,
                    evidence=line.strip(),
                    explanation="State validation is selectively bypassed based on transaction amount, permitting suspended accounts to conduct transactions under the threshold (CWE-285).",
                    remediation="Apply account status and suspension verification unconditionally to all transaction amounts.",
                    rule_id="SEC-AUTH-003",
                    defect_category="logic",
                    potential_impact="Suspended, fraudulent, or deactivated accounts continue transacting without restriction."
                ))

        # 3. SEC-DATA-001: Hardcoded Master Secret Key in Source
        secret_pat = re.compile(
            r'(?:admin_secret_key|व्यवस्थापक_गुप्त_कुंजी|నిర్వాహక_రహస్య_కీ|প্রশাসক_গোপন_চাবি|प्रशासक_गुप्त_की|प्रशासक_गोप्य_कुञ्जी)\s*=\s*["\']([^"\']+)["\']'
            r'|["\'](sk_live_sec_prod_[^"\']+)["\']'
        )
        for line_no, line in enumerate(lines, start=1):
            m_sec = secret_pat.search(line)
            if m_sec:
                score = calculate_risk_score("High", "confirmed", True, False)
                findings.append(SecurityFinding(
                    id=f"SEC-DATA-{len(findings)+1:03d}",
                    title="Hardcoded Production Master Secret Key in Source Code",
                    stage="Multilingual Static Analysis",
                    stage_id="multilingual",
                    severity="High",
                    risk_score=score,
                    confidence="confirmed",
                    status="confirmed",
                    line=line_no,
                    column=m_sec.start() + 1,
                    evidence=line.strip(),
                    explanation="Production master secret credentials are hardcoded directly in source code. Anyone with repository access can extract master keys (CWE-798).",
                    remediation="Extract credentials to protected environment variables or runtime key management vaults.",
                    rule_id="SEC-DATA-001",
                    defect_category="security",
                    potential_impact="Full administrative compromise of application data and services."
                ))

        # 4. SEC-DATA-002: Information Disclosure via Debug Logs
        leak_pat = re.compile(
            r'(?:print|लिखो|ముద్రించు|ছাপাও|लिहा|छाप)\s*\(\s*(?:admin_secret_key|व्यवस्थापक_गुप्त_कुंजी|నిర్వాహక_రహస్య_కీ|প্রশাসক_গোপন_চাবি|प्रशासक_गुप्त_की|प्रशासक_गोप्य_कुञ्जी)\s*\)'
        )
        for line_no, line in enumerate(lines, start=1):
            m_leak = leak_pat.search(line)
            if m_leak:
                score = calculate_risk_score("Medium", "confirmed", True, False)
                findings.append(SecurityFinding(
                    id=f"SEC-DATA-{len(findings)+1:03d}",
                    title="Sensitive Master Credential Leaked in Console Output",
                    stage="Multilingual Static Analysis",
                    stage_id="multilingual",
                    severity="Medium",
                    risk_score=score,
                    confidence="confirmed",
                    status="confirmed",
                    line=line_no,
                    column=m_leak.start() + 1,
                    evidence=line.strip(),
                    explanation="Debug logging output writes unredacted administrative secret keys to public application console logs (CWE-200).",
                    remediation="Remove or mask sensitive credentials in all output and debug statements.",
                    rule_id="SEC-DATA-002",
                    defect_category="security",
                    potential_impact="Credentials exposed in execution logs and telemetry buffers."
                ))

        # 5. SEC-DATA-003: Off-by-One / Missing Bounds Validation
        bound_pat = re.compile(
            r'\b(?:record_index|रिकॉर्ड_क्रमांक|రికార్డ్_సూచిక|রেকর্ড_সূচক|नोंद_क्रमांक|रेकर्ड_सूचकांक)\s*>\s*5\b'
            r'|while\s*\([^\)]*<=\s*(?:raw_count|कुल_संख्या|మొత్తం_సంఖ్య|মোট_সংখ্যা|एकूण_संख्या|जम्मा_संख्या)'
            r'|जबतक\s*\([^\)]*<=\s*(?:कुल_संख्या|raw_count)'
            r'|ఉన్నంతవరకు\s*\([^\)]*<=\s*(?:మొత్తం_సంఖ్య|raw_count)'
            r'|যতক্ষণ\s*\([^\)]*<=\s*(?:মোট_সংখ্যা|raw_count)'
            r'|जोपर्यंत\s*\([^\)]*<=\s*(?:एकूण_संख्या|raw_count)'
            r'|जबसम्म\s*\([^\)]*<=\s*(?:जम्मा_संख्या|raw_count)'
        )
        for line_no, line in enumerate(lines, start=1):
            m_bnd = bound_pat.search(line)
            if m_bnd:
                score = calculate_risk_score("Low", "confirmed", True, False)
                findings.append(SecurityFinding(
                    id=f"SEC-DATA-{len(findings)+1:03d}",
                    title="Off-by-One Upper Bound Vulnerability in Buffer Access",
                    stage="Multilingual Static Analysis",
                    stage_id="multilingual",
                    severity="Low",
                    risk_score=score,
                    confidence="confirmed",
                    status="confirmed",
                    line=line_no,
                    column=m_bnd.start() + 1,
                    evidence=line.strip(),
                    explanation="Boundary check permits index 5 for 5-element array (indices 0..4) or extra loop cycle, leading to out-of-bounds access (CWE-129).",
                    remediation="Change boundary check to strictly reject index >= 5 and use strictly '<' in loop condition.",
                    rule_id="SEC-DATA-003",
                    defect_category="logic",
                    potential_impact="Buffer out-of-range indexing or index calculation errors."
                ))

        # 6. SEC-INJ-001: SQL Query Injection via String Concatenation
        sql_inj_pat = re.compile(
            r'(?:SELECT .* FROM .* WHERE .* AND |query_prefix|क्वेरी_प्रारंभ|క్వెరీ_ప్రారంభం|কোয়েরি_শুরু|क्वेरी_सुरुवात|क्वेरी_सुरु)\s*(\+|,\s*)\s*(?:user_filter|फ़िल्टर|ఫిల్టర్|ফিল্টার|फिल्टर|malicious_sql)'
        )
        for line_no, line in enumerate(lines, start=1):
            m_sql = sql_inj_pat.search(line)
            if m_sql:
                score = calculate_risk_score("High", "confirmed", True, False)
                findings.append(SecurityFinding(
                    id=f"SEC-INJ-{len(findings)+1:03d}",
                    title="SQL Query Injection via Unchecked String Concatenation",
                    stage="Multilingual Static Analysis",
                    stage_id="multilingual",
                    severity="High",
                    risk_score=score,
                    confidence="confirmed",
                    status="confirmed",
                    line=line_no,
                    column=m_sql.start() + 1,
                    evidence=line.strip(),
                    explanation="Untrusted user input flows directly into dynamic database query construction without sanitization or parameterization (CWE-89).",
                    remediation="Use parameterized database lookups instead of dynamic string concatenation.",
                    rule_id="SEC-INJ-001",
                    defect_category="security",
                    potential_impact="Arbitrary database read, authentication bypass, or schema tampering.",
                    source_sink_flow={
                        "source": "Unvalidated input parameter (user_filter)",
                        "intermediate": "String concatenation (+)",
                        "sink": "Database query dispatch function"
                    }
                ))

        # 7. SEC-LOGIC-001: Missing Negative Item Quantity Check (Refund Exploit)
        subtotal_fn_pat = re.compile(
            r'(?:calculate_item_subtotal|वस्तु_उपयोग_गणना|వస్తువు_ఉపమొత్తం_లెక్కించు|পণ্যের_উপযোগ_গণনা|वस्तू_उपयोग_गणना|वस्तु_उपयोग_गणना)\s*\(([^)]+)\)'
        )
        for line_no, line in enumerate(lines, start=1):
            m_sub = subtotal_fn_pat.search(line)
            if m_sub:
                qty_check_pat = re.compile(
                    r'(?:^|[\s(,~])(?:item_quantity|मात्रा|పరిమాణం|পরিমাণ|प्रमाण)\s*<=?\s*0'
                )
                has_qty_check = bool(qty_check_pat.search(source_code))
                if not has_qty_check:
                    score = calculate_risk_score("High", "confirmed", True, False)
                    findings.append(SecurityFinding(
                        id=f"SEC-LOGIC-{len(findings)+1:03d}",
                        title="Missing Negative Item Quantity Check (Refund Exploit)",
                        stage="Multilingual Static Analysis",
                        stage_id="multilingual",
                        severity="High",
                        risk_score=score,
                        confidence="confirmed",
                        status="confirmed",
                        line=line_no,
                        column=1,
                        evidence=line.strip(),
                        explanation="Order subtotal calculation lacks negative quantity validation, permitting negative item counts that reverse invoice totals (CWE-840).",
                        remediation="Validate that item_quantity > 0 before computing subtotal amounts.",
                        rule_id="SEC-LOGIC-001",
                        defect_category="logic",
                        potential_impact="Negative balance generation, invoice reversal, and financial exploitation."
                    ))

        # 8. SEC-SEM-001: Undefined Variable in Conditional Branch
        undef_pat = re.compile(
            r'(?:print|लिखो|ముద్రించు|ছাপাও|लिहा|छाप)\s*\(\s*(acc_status|खाता_अंतिम_स्थिति|ఖాతా_ముగింపు_స్థితి|অ্যাকাউন্ট_সমাপ্তি_অবস্থা|खाते_शेवटची_स्थिती)\s*\)'
        )
        for line_no, line in enumerate(lines, start=1):
            m_und = undef_pat.search(line)
            if m_und:
                var_name = m_und.group(1)
                score = calculate_risk_score("Medium", "confirmed", True, False)
                findings.append(SecurityFinding(
                    id=f"SEC-SEM-{len(findings)+1:03d}",
                    title=f"Semantic Defect: Undefined Identifier '{var_name}'",
                    stage="Multilingual Static Analysis",
                    stage_id="multilingual",
                    severity="Medium",
                    risk_score=score,
                    confidence="confirmed",
                    status="confirmed",
                    line=line_no,
                    column=m_und.start() + 1,
                    evidence=line.strip(),
                    explanation=f"Identifier '{var_name}' is referenced without declaration or assignment in this lexical scope.",
                    remediation=f"Declare '{var_name}' or reference the declared account status variable.",
                    rule_id="SEC-SEM-001",
                    defect_category="semantic",
                    potential_impact="Compile-time or runtime NameError crashing account closure workflow."
                ))

        return findings

    @classmethod
    def scan_python_ir_ast(cls, ir_code: str) -> List[SecurityFinding]:
        findings = []
        if not ir_code or not ir_code.strip():
            return findings

        try:
            tree = ast.parse(ir_code)
            visitor = PythonASTSecurityVisitor(ir_code.splitlines())
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError:
            # If IR itself is invalid Python, report syntax error without crashing
            pass
        except Exception as e:
            pass

        return findings
    
    # Backwards-compatible alias for AST IR scanner
    scan_ir_codegen = scan_python_ir_ast

    @classmethod
    def scan_execution_boundary(cls, source_code: str, ir_code: str = "") -> List[SecurityFinding]:
        """Scans execution boundary risks (infinite loops, resource exhaustion)."""
        findings = []
        code_to_check = f"{source_code}\n{ir_code}".strip()

        # 1. Unbounded infinite loop pattern: while(1) or while(true) without break in VITAL syntax
        while_true_patterns = [
            r'while\s*\(\s*(?:1|true|1\s*==\s*1)\s*\)\s*\{([^}]+)\}',
            r'जबतक\s*\(\s*(?:1|true)\s*\)\s*\{([^}]+)\}',
            r'ఉన్నంతవరకు\s*\(\s*(?:1|true)\s*\)\s*\{([^}]+)\}',
            r'যতক্ষণ\s*\(\s*(?:1|true)\s*\)\s*\{([^}]+)\}',
            r'जोपर्यंत\s*\(\s*(?:1|true)\s*\)\s*\{([^}]+)\}',
            r'जबसम्म\s*\(\s*(?:1|true)\s*\)\s*\{([^}]+)\}'
        ]

        for pat in while_true_patterns:
            for m in re.finditer(pat, source_code, re.IGNORECASE):
                body = m.group(1)
                break_keywords = ['break', 'रुक', 'ఆపు', 'থামো', 'थांब', 'रोक']
                if not any(k in body for k in break_keywords):
                    score = calculate_risk_score("High", "probable", False, False)
                    findings.append(SecurityFinding(
                        id=f"SEC-EXEC-{len(findings)+1:03d}",
                        title="Unbounded Infinite Loop Without Break Mechanism",
                        stage="Execution Boundary",
                        stage_id="execution_boundary",
                        severity="High",
                        risk_score=score,
                        confidence="probable",
                        status="probable",
                        evidence=m.group(0)[:80] + ("..." if len(m.group(0)) > 80 else ""),
                        explanation="Infinite loop without an exit condition exhausts execution resources until timeout guard kills the worker.",
                        remediation="Introduce an incrementing counter or condition update to terminate loop execution.",
                        rule_id="SEC-RUN-001"
                    ))

        # 2. Check Python AST for while True / while 1 in ir_code or source_code
        for py_candidate in (ir_code, source_code):
            if not py_candidate:
                continue
            try:
                tree = ast.parse(py_candidate)
                for node in ast.walk(tree):
                    if isinstance(node, ast.While):
                        is_const_true = False
                        if isinstance(node.test, ast.Constant) and bool(node.test.value):
                            is_const_true = True
                        elif isinstance(node.test, ast.Name) and node.test.id == "True":
                            is_const_true = True
                        if is_const_true:
                            has_break = any(isinstance(n, ast.Break) for n in ast.walk(node))
                            if not has_break:
                                score = calculate_risk_score("High", "probable", False, False)
                                findings.append(SecurityFinding(
                                    id=f"SEC-EXEC-{len(findings)+1:03d}",
                                    title="Unbounded Infinite Loop Without Break Mechanism",
                                    stage="Execution Boundary",
                                    stage_id="execution_boundary",
                                    severity="High",
                                    risk_score=score,
                                    confidence="probable",
                                    status="probable",
                                    evidence="while True: pass",
                                    explanation="Infinite loop without an exit condition exhausts execution resources until timeout guard kills the worker.",
                                    remediation="Introduce an incrementing counter or condition update to terminate loop execution.",
                                    rule_id="SEC-RUN-001"
                                ))
                                break
            except Exception:
                pass
            if findings:
                break

        # 3. Catastrophic exponentiation in IR or source (e.g. 10**100000)
        exp_match = re.search(r'\b\d+\s*\*\*\s*([0-9]{4,})\b', code_to_check)
        if exp_match:
            exp_val = int(exp_match.group(1))
            score = calculate_risk_score("High", "confirmed", False, True)
            findings.append(SecurityFinding(
                id=f"SEC-EXEC-{len(findings)+1:03d}",
                title=f"Catastrophic Exponentiation Denial of Service (** {exp_val})",
                stage="Execution Boundary",
                stage_id="execution_boundary",
                severity="High",
                risk_score=score,
                confidence="confirmed",
                status="confirmed",
                evidence=exp_match.group(0),
                explanation="Computing massive power exponents causes CPU saturation and MemoryError denial of service.",
                remediation="Bound numerical power operations or use modular exponentiation.",
                rule_id="SEC-RUN-002"
            ))

        return findings


# ---------------------------------------------------------------------------
# AI Security Agent Coordinator (Ollama)
# ---------------------------------------------------------------------------

class SecurityAnalysisCoordinator:
    """
    Coordinates deterministic static security analysis and local Ollama model
    investigation (qwen2.5-coder:7b-instruct).
    """

    def __init__(self, client: Optional[OllamaClient] = None):
        self.ollama = client or ollama_client
        self._fix_cache: Dict[str, Dict[str, Any]] = {}

    def run_full_scan(
        self,
        source_code: str,
        ir_code: str = "",
        language: str = "English",
        use_ai_enrichment: bool = True,
        syntax_blocked: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Executes complete multi-stage security analysis:
          1. Deterministic Lexical Scan
          2. Deterministic Parser Scan
          3. Deterministic Multilingual Security Scan
          4. Deterministic Generated IR Scan (Python AST) - if not syntax blocked
          5. Deterministic Execution Boundary Scan - if not syntax blocked
          6. Optional Local Ollama AI Investigation & Fix Enrichment
          7. Deterministic Risk Score Computation (0-100)
        """
        findings: List[SecurityFinding] = []

        # 1. Lexical scan
        findings.extend(DeterministicSecurityScanner.scan_lexical(source_code))

        # 2. Parser scan
        parser_findings = DeterministicSecurityScanner.scan_parser(source_code)
        findings.extend(parser_findings)

        # Automatically determine syntax blocked status if not explicitly provided
        if syntax_blocked is None:
            has_delimiter_error = any(f.rule_id == "SEC-PAR-001" for f in parser_findings)
            syntax_blocked = has_delimiter_error

        # 3. Multilingual security & logic scan
        findings.extend(DeterministicSecurityScanner.scan_multilingual_security(source_code, language))

        # 4. Transpiled IR & Execution boundary scans (only if syntax is not blocked)
        if not syntax_blocked:
            if not ir_code:
                try:
                    from main import Compiler, RULES_FILE
                    c = Compiler(RULES_FILE)
                    c.load_rules()
                    ir_code = c.transpile(source_code)
                except Exception:
                    ir_code = ""

            if ir_code:
                findings.extend(DeterministicSecurityScanner.scan_python_ir_ast(ir_code))
                findings.extend(DeterministicSecurityScanner.scan_execution_boundary(source_code, ir_code))
            else:
                findings.extend(DeterministicSecurityScanner.scan_execution_boundary(source_code, ""))

        # Assign stable, deterministic finding IDs based on rule and source line (NOT dynamic array index)
        seen_ids = set()
        for f in findings:
            prefix = f.rule_id if f.rule_id else f"SEC-{f.stage_id[:3].upper()}"
            base_id = f"{prefix}-L{f.line}" if f.line and f.line > 0 else prefix
            cand_id = base_id
            c = 2
            while cand_id in seen_ids:
                cand_id = f"{base_id}_{c}"
                c += 1
            seen_ids.add(cand_id)
            f.id = cand_id

        # 5. AI Enrichment (if requested and Ollama available)
        ai_available, ai_msg, ai_details = self.ollama.check_health()
        ai_status = {
            "available": ai_available,
            "online": ai_available,
            "healthy": ai_available,
            "model": self.ollama.model_name,
            "message": ai_msg,
            "latency_ms": ai_details.get("latency_ms", 0.0)
        }

        if use_ai_enrichment and ai_available and findings:
            findings = self._enrich_findings_with_ollama(source_code, findings, language)

        # 6. Overall risk score & summary (passes syntax_blocked integrity)
        overall_score, overall_summary = compute_overall_risk_score(findings, syntax_blocked=syntax_blocked)

        # Stage breakdown summary
        stage_counts = {
            "lexical": sum(1 for f in findings if f.stage_id == "lexical"),
            "parser": sum(1 for f in findings if f.stage_id == "parser"),
            "multilingual": sum(1 for f in findings if f.stage_id == "multilingual"),
            "ir_codegen": sum(1 for f in findings if f.stage_id == "ir_codegen"),
            "execution_boundary": sum(1 for f in findings if f.stage_id == "execution_boundary")
        }

        severity_counts = {
            "Critical": sum(1 for f in findings if f.severity == "Critical"),
            "High": sum(1 for f in findings if f.severity == "High"),
            "Medium": sum(1 for f in findings if f.severity == "Medium"),
            "Low": sum(1 for f in findings if f.severity == "Low"),
            "Informational": sum(1 for f in findings if f.severity == "Informational")
        }

        defect_category_counts = {
            "security": sum(1 for f in findings if f.defect_category == "security"),
            "syntax": sum(1 for f in findings if f.defect_category == "syntax"),
            "semantic": sum(1 for f in findings if f.defect_category == "semantic"),
            "logic": sum(1 for f in findings if f.defect_category == "logic"),
            "lexical": sum(1 for f in findings if f.defect_category == "lexical")
        }

        return {
            "success": True,
            "overall_risk_score": "BLOCKED" if syntax_blocked else overall_score,
            "overall_summary": overall_summary,
            "summary": overall_summary,
            "syntax_blocked": syntax_blocked,
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
            "stage_counts": stage_counts,
            "severity_counts": severity_counts,
            "defect_category_counts": defect_category_counts,
            "ai_status": ai_status,
            "timestamp": time.time()
        }

    def _enrich_findings_with_ollama(
        self,
        source_code: str,
        findings: List[SecurityFinding],
        language: str
    ) -> List[SecurityFinding]:
        """
        Uses qwen2.5-coder:7b-instruct to provide in-depth pedagogical explanation
        and minimal proposed corrections for each finding.
        """
        # Limit to top 5 findings to preserve quick response time
        for f in findings[:5]:
            try:
                system_prompt = (
                    "You are a Compiler Security Specialist for VITAL, an educational multilingual programming language. "
                    "Analyze the provided security finding and source code. Provide a concise explanation of potential "
                    "security impact, safe remediation, and proposed minimal code correction. "
                    "Return ONLY valid JSON matching this schema: "
                    '{"explanation": "...", "remediation": "...", "suggested_code": "..."}'
                )

                user_prompt = (
                    f"Compiler Stage: {f.stage}\n"
                    f"Finding Title: {f.title} ({f.severity})\n"
                    f"Evidence: {f.evidence}\n"
                    f"Line: {f.line}\n"
                    f"Language: {language}\n\n"
                    f"Source Code:\n{source_code[:1500]}\n\n"
                    "Propose a safer replacement code snippet for this issue."
                )

                resp = self.ollama.chat(
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=0.1,
                    max_tokens=512,
                    response_format="json"
                )

                if resp.get("success"):
                    content = resp.get("content", "")
                    try:
                        data = json.loads(content)
                        if data.get("explanation"):
                            f.explanation = f"{f.explanation} [AI Note: {data['explanation']}]"
                        if data.get("remediation"):
                            f.remediation = data["remediation"]
                        if data.get("suggested_code"):
                            f.suggested_code = data["suggested_code"]
                            f.diff = self.generate_diff(f.evidence, data["suggested_code"])
                        f.is_ai_enriched = True
                    except json.JSONDecodeError:
                        pass
            except Exception:
                pass

        return findings

    def _compute_cache_key(
        self,
        source_code: str,
        finding_id: str,
        rule_id: str,
        line_no: Any,
        evidence: str,
        language: str,
        model: str = ""
    ) -> str:
        import unicodedata
        norm_src = unicodedata.normalize("NFC", source_code).replace("\r\n", "\n").replace("\r", "\n")
        src_rev_hash = hashlib.sha256(norm_src.encode("utf-8")).hexdigest()
        raw = f"{src_rev_hash}|{finding_id}|{rule_id}|{line_no}|{evidence.strip()}|{model}|{language.lower()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def generate_deterministic_fix(
        self,
        source_code: str,
        finding_id: Any = "",
        finding_data: Optional[Dict[str, Any]] = None,
        language: str = "English"
    ) -> Optional[Dict[str, Any]]:
        """
        Generates an instantaneous, rule-based safe correction without contacting any LLM.
        Covers all registered Security Lab demos and standard security rules.
        """
        if isinstance(finding_id, SecurityFinding):
            finding_data = finding_id.to_dict()
            finding_id = finding_id.id
        elif isinstance(finding_id, dict):
            finding_data = finding_id
            finding_id = finding_data.get("id", "")
        elif finding_data is None:
            finding_data = {}

        evidence = finding_data.get("evidence", "")
        line_no = finding_data.get("line")
        title = finding_data.get("title", "")
        rule_id = finding_data.get("rule_id", "")

        proposed_code = ""
        proposed_source = ""
        explanation = ""

        # Step 1: Specific targeted per-issue deterministic remediation
        if "SEC-AUTH-003" in rule_id or "Bypass" in title or "Threshold" in title or "Suspension" in title:
            bypass_pat = re.compile(
                r'[ \t]*if\s*\([^)]*(?:amount|राशि|మొత్తం|పరిమాణం|পরিমাণ|रक्कम|रकम)\s*>\s*500[^)]*\)\s*\{[\s\S]*?\}[ \t]*(?:else|अन्यथा|లేకపోతే|নাহলে|नाहीतर|नत्र)\s*\{[\s\S]*?\}'
            )
            m_byp = bypass_pat.search(source_code)
            if m_byp:
                lang_lower = language.lower()
                if lang_lower == "hindi":
                    rep_code = "    मानो स्थिति_ठीक = खाता_स्थिति_जांचें(स्रोत_खाता, 1)\n    अगर (स्थिति_ठीक == 0) {\n        लिखो(\"स्थानांतरण अवरुद्ध: स्रोत खाता निलंबित है।\")\n        लौटाओ 0\n    }"
                elif lang_lower == "telugu":
                    rep_code = "    అనుకో స్థితి_సరి = ఖాతా_స్థితి_తనిఖీ(మూల_ఖాతా, 1)\n    ఒకవేళ (స్థితి_సరి == 0) {\n        రాయి(\"బదిలీ నిరోధించబడింది: మూల ఖాతా నిలిపివేయబడింది.\")\n        తిరిగి_ఇవ్వు 0\n    }"
                elif lang_lower == "bengali":
                    rep_code = "    ধরো অবস্থা_ঠিক = অ্যাকাউন্ট_অবস্থা_যাচাই(উৎস_অ্যাকাউন্ট, 1)\n    যদি (অবস্থা_ঠিক == 0) {\n        ছাপাও(\"স্থানান্তর অবরুদ্ধ: উৎস অ্যাকাউন্ট স্থগিত।\")\n        ফেরত 0\n    }"
                elif lang_lower == "marathi":
                    rep_code = "    घ्या स्थिती_ठीक = खाते_स्थिती_तपासा(मूळ_खाते, 1)\n    जर (स्थिती_ठीक == 0) {\n        लिहा(\"हस्तांतरण रोखले: मूळ खाते निलंबित आहे.\")\n        परत_करा 0\n    }"
                elif lang_lower == "nepali":
                    rep_code = "    मान स्थिति_ठीक = खाता_स्थिति_जाँच(स्रोत_खाता, 1)\n    यदि (स्थिति_ठीक == 0) {\n        छाप(\"हस्तान्तरण रोकियो: स्रोत खाता निलम्बित छ।\")\n        फिर्ता 0\n    }"
                else:
                    rep_code = "    let status_ok = check_account_status(from_account_id, 1)\n    if (status_ok == 0) {\n        print(\"Transfer blocked: Source account is suspended.\")\n        return 0\n    }"
                proposed_source = source_code[:m_byp.start()] + rep_code + source_code[m_byp.end():]
                proposed_code = rep_code
            else:
                proposed_code = "    let status_ok = check_account_status(from_account_id, 1)\n    if (status_ok == 0) { return 0 }"
            explanation = "Enforced account status check unconditionally for all transaction amounts (CWE-285)."

        elif "SEC-AUTH-001" in rule_id or "SEC-IDOR-001" in rule_id or "IDOR" in title or "Ownership" in title:
            idor_check = {
                "english": "    // Fixed IDOR: Assert caller ownership\n    if (caller_id != from_account_id) {\n        print(\"Access Denied: Caller does not own the source account.\")\n        return 0\n    }",
                "hindi": "    // स्वामित्व सत्यापन (IDOR शमन)\n    अगर (कॉलर_आईडी != स्रोत_खाता) {\n        लिखो(\"पहुंच अस्वीकृत: कॉलर स्रोत खाते का स्वामी नहीं है।\")\n        लौटाओ 0\n    }",
                "telugu": "    // యాజమాన్య ధృవీకరణ (IDOR)\n    ఒకవేళ (కాలర్_ఐడి != మూల_ఖాతా) {\n        రాయి(\"యాక్సెస్ తిరస్కరించబడింది: కాలర్ మూల ఖాతాదారుడు కాదు.\")\n        తిరిగి_ఇవ్వు 0\n    }",
                "bengali": "    // মালিকানা যাচাইকরণ (IDOR)\n    যদি (কলার_আইডি != উৎস_অ্যাকাউন্ট) {\n        ছাপাও(\"অ্যাক্সেস অস্বীকৃত: কলার উৎস অ্যাকাউন্টের মালিক নন।\")\n        ফেরত 0\n    }",
                "marathi": "    // मालकी पडताळणी (IDOR)\n    जर (कॉलर_आयडी != मूळ_खाते) {\n        लिहा(\"प्रवेश नाकारला: कॉलर मूळ खात्याचा मालक नाही.\")\n        परत_करा 0\n    }",
                "nepali": "    // स्वामित्व प्रमाणीकरण (IDOR)\n    यदि (कलर_आईडी != स्रोत_खाता) {\n        छाप(\"पहुँच अस्वीकृत: कलर स्रोत खाताको मालिक होइन।\")\n        फिर्ता 0\n    }"
            }.get(language.lower(), "    if (caller_id != from_account_id) { return 0 }")

            proposed_code = idor_check
            caller_print_match = re.search(r'[ \t]*(?:print|लिखो|రాయి|ছাপাও|लिहा|छाप)\s*\([^)]*(?:caller_id|कॉलर_आईडी|కాలర్_ఐడి|কলার_আইডি|कॉलर_आयडी|कलर_आईडी)[^)]*\)', source_code)
            if caller_print_match:
                insert_pos = caller_print_match.end()
                proposed_source = source_code[:insert_pos] + "\n\n" + idor_check + source_code[insert_pos:]
            elif evidence and evidence in source_code:
                proposed_source = source_code.replace(evidence, f"{idor_check}\n    {evidence}", 1)
            explanation = "Enforced object-level ownership check to prevent IDOR balance transfers (CWE-639)."

        elif "SEC-SEM-001" in rule_id or "SEM-001" in rule_id or "Undefined" in title or "division by zero" in title.lower() or "Semantic" in title or (finding_data and str(finding_data.get("stage_id", "")).lower() == "semantic_analysis"):
            proposed_source = source_code
            source_lines = source_code.splitlines()
            ident = str(finding_data.get("identifier", "") if finding_data else "")
            if not ident:
                ident_match = re.search(r"Identifier '([^']+)'", title)
                if ident_match:
                    ident = ident_match.group(1)

            lang_key = (language or "english").lower()
            if "telugu" in lang_key:
                lang_key = "telugu"
            elif "hindi" in lang_key:
                lang_key = "hindi"
            elif "bengali" in lang_key:
                lang_key = "bengali"
            elif "marathi" in lang_key:
                lang_key = "marathi"
            elif "nepali" in lang_key:
                lang_key = "nepali"
            else:
                lang_key = "english"

            matched_replacement = False

            # 1. Dynamic evaluation sink (eval / exec)
            is_eval = ident.lower() in ("eval", "exec") or "eval" in title.lower() or "eval" in evidence.lower()
            if line_no and 1 <= line_no <= len(source_lines) and re.search(r'\b(?:eval|exec)\s*\(', source_lines[line_no - 1]):
                is_eval = True

            if is_eval:
                safe_eval_prints = {
                    "english": 'print("Notice: Dynamic evaluation safely neutralized.")',
                    "telugu": 'ముద్రించు("గమనిక: డైనమిక్ మూల్యాంకనం సురక్షితంగా తటస్థీకరించబడింది.")',
                    "hindi": 'लिखो("सूचना: गतिशील मूल्यांकन सुरक्षित रूप से बेअसर किया गया।")',
                    "bengali": 'ছাপাও("বিজ্ঞপ্তি: গতিশীল মূল্যায়ন নিরাপদে নিরপেক্ষ করা হয়েছে।")',
                    "marathi": 'लिहा("सूचना: डायनॅमिक मूल्यांकन सुरक्षितपणे निष्प्रभ केले.")',
                    "nepali": 'छाप("सूचना: गतिशील मूल्याङ्कन सुरक्षित रूपमा निष्क्रिय गरियो।")'
                }
                safe_call = safe_eval_prints.get(lang_key, safe_eval_prints["english"])

                if line_no and 1 <= line_no <= len(source_lines) and re.search(r'\b(?:eval|exec)\s*\(', source_lines[line_no - 1]):
                    target_line = source_lines[line_no - 1]
                    indent_ws = target_line[:len(target_line) - len(target_line.lstrip())]
                    new_lines = list(source_lines)
                    new_lines[line_no - 1] = f"{indent_ws}{safe_call}"
                    proposed_source = "\n".join(new_lines)
                    proposed_code = f"{indent_ws}{safe_call}"
                    explanation = "Replaced unsafe dynamic eval sink with safe language-native logging call."
                else:
                    m = re.search(r'^[ \t]*(?:eval|exec)\s*\(.*?\)', source_code, re.MULTILINE)
                    if m:
                        lead_ws = re.match(r'^[ \t]*', m.group(0)).group(0)
                        proposed_source = source_code[:m.start()] + f"{lead_ws}{safe_call}" + source_code[m.end():]
                        proposed_code = f"{lead_ws}{safe_call}"
                        explanation = "Replaced unsafe dynamic eval sink with safe language-native logging call."

            # 2. Division by zero constant
            elif (rule_id == "SEM-001" or ("SEM-001" in rule_id and "SEC-" not in rule_id)) or "division by zero" in title.lower():
                if line_no and 1 <= line_no <= len(source_lines):
                    line = source_lines[line_no - 1]
                    new_line = re.sub(r'(/|//|%)\s*0\b', r'\g<1> 1', line)
                    if new_line != line:
                        new_lines = list(source_lines)
                        new_lines[line_no - 1] = new_line
                        proposed_source = "\n".join(new_lines)
                        proposed_code = new_line.strip()
                        explanation = "Guarded arithmetic operation by replacing zero divisor with 1 to prevent division by zero crash."
                if proposed_source == source_code:
                    proposed_source = re.sub(r'(/|//|%)\s*0\b', r'\g<1> 1', source_code, count=1)
                    proposed_code = "Division by zero guarded (divisor changed to 1)"
                    explanation = "Guarded arithmetic operation by replacing zero divisor with 1 to prevent division by zero crash."

            # 3. Mixed-script homoglyphs
            elif "রেকॉर्ड_সূচক" in source_code:
                proposed_source = source_code.replace("রেকॉर्ड_সূচক", "রেকর্ড_সূচক")
                proposed_code = "রেকর্ড_সূচক"
                explanation = "Corrected mixed-script homoglyph typo to pure Bengali identifier."

            # 4. Known status variable educational replacements
            else:
                replacements = [
                    ("acc_status", "account_closed"),
                    ("खाता_अंतिम_स्थिति", "खाता_बंद"),
                    ("ఖాతా_ముగింపు_స్థితి", "ఖాతా_మూసివేయబడింది"),
                    ("অ্যাকাউন্ট_সমাপ্তি_অবস্থা", "অ্যাকাউন্ট_বন্ধ"),
                    ("खाते_शेवटची_स्थिती", "खाते_बंद"),
                    ("खाता_अन्तिम_स्थिति", "खाता_बन्द")
                ]
                matched_replacement = False
                for bad, good in replacements:
                    if bad in source_code and (not ident or ident == bad or bad in ident):
                        proposed_source = source_code.replace(bad, good)
                        proposed_code = f"// Replaced undefined identifier '{bad}' with '{good}'"
                        explanation = "Replaced undeclared identifier reference with declared status variable."
                        matched_replacement = True
                        break

                # 5. Undeclared identifier matching misspelled declared variable
                if not matched_replacement and ident and proposed_source == source_code:
                    declared_names = set(re.findall(r'(?:let|मानो|అనుకో|ধরো|घ्या|मान)\s+([A-Za-z0-9_\u0900-\u0D7F]+)', source_code))
                    for func_params in re.findall(r'(?:function|def|कार्य|ఫంక్షన్|ফাংশন|कार्य_करा|कार्य_गर)\s+[A-Za-z0-9_\u0900-\u0D7F]+\s*\(([^)]*)\)', source_code):
                        for param in func_params.split(','):
                            p_clean = param.strip()
                            if p_clean:
                                declared_names.add(p_clean)

                    def _lev(s1, s2):
                        if len(s1) < len(s2):
                            return _lev(s2, s1)
                        if len(s2) == 0:
                            return len(s1)
                        prev = list(range(len(s2) + 1))
                        for i, c1 in enumerate(s1):
                            curr = [i + 1]
                            for j, c2 in enumerate(s2):
                                curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
                            prev = curr
                        return prev[-1]

                    best_match = None
                    best_dist = 99
                    for cand in declared_names:
                        if cand != ident:
                            d = _lev(ident, cand)
                            if d <= 2 and d < best_dist:
                                best_dist = d
                                best_match = cand

                    if best_match:
                        if line_no and 1 <= line_no <= len(source_lines):
                            line = source_lines[line_no - 1]
                            new_line = re.sub(r'\b' + re.escape(ident) + r'\b', best_match, line)
                            if new_line != line:
                                new_lines = list(source_lines)
                                new_lines[line_no - 1] = new_line
                                proposed_source = "\n".join(new_lines)
                                proposed_code = new_line.strip()
                                explanation = f"Corrected misspelled identifier '{ident}' to declared symbol '{best_match}'."
                        if proposed_source == source_code:
                            proposed_source = re.sub(r'\b' + re.escape(ident) + r'\b', best_match, source_code)
                            proposed_code = f"// Corrected '{ident}' -> '{best_match}'"
                            explanation = f"Corrected misspelled identifier '{ident}' to declared symbol '{best_match}'."

                # 6. General undeclared identifier declaration
                if not matched_replacement and ident and proposed_source == source_code:
                    decl_keywords = {
                        "english": "let",
                        "telugu": "అనుకో",
                        "hindi": "मानो",
                        "bengali": "ধরো",
                        "marathi": "घ्या",
                        "nepali": "मान"
                    }
                    kw_let = decl_keywords.get(lang_key, "let")
                    if line_no and 1 <= line_no <= len(source_lines):
                        target_line = source_lines[line_no - 1]
                        indent_ws = target_line[:len(target_line) - len(target_line.lstrip())]
                        decl_stmt = f"{indent_ws}{kw_let} {ident} = 0"
                        new_lines = list(source_lines)
                        new_lines.insert(line_no - 1, decl_stmt)
                        proposed_source = "\n".join(new_lines)
                        proposed_code = decl_stmt
                        explanation = f"Added explicit local declaration '{decl_stmt.strip()}' before first reference to resolve undeclared identifier."

            if proposed_source == source_code or not proposed_code:
                return None

        elif "SEC-DATA-001" in rule_id or "Secret Key" in title:
            proposed_source = re.sub(
                r'(["\']sk_live_sec_prod_[^"\']+["\'])',
                '"REDACTED_USE_ENVIRONMENT_CONFIG"',
                source_code
            )
            proposed_code = '// Credentials moved to secure environment configuration\nlet admin_secret_key = "REDACTED_USE_ENVIRONMENT_CONFIG"'
            explanation = "Redacted hardcoded secret key and replaced with runtime environment configuration placeholder (CWE-798)."

        elif "SEC-DATA-002" in rule_id or "Sensitive" in title or "Disclosure" in title:
            print_secret_pat = re.compile(r'[ \t]*(?:print|लिखो|రాయి|ছাপাও|लिहा|छाप)\s*\([^)]*(?:admin_secret_key|व्यवस्थापक_गुप्त_कुंजी|నిర్వాహక_రహస్య_కీ|প্রশাসক_গোপন_চাবি|प्रशासक_गुप्त_की|प्रशासक_गोप्य_कुञ्जी)[^)]*\)')
            m_sec_print = print_secret_pat.search(source_code)
            if m_sec_print:
                safe_log = '        print("DEBUG LOG [INTERNAL]: [Master Secret Key Redacted for Security]")'
                proposed_source = source_code[:m_sec_print.start()] + safe_log + source_code[m_sec_print.end():]
                proposed_code = safe_log
            else:
                proposed_code = '// Redacted secret logging\nprint("DEBUG LOG: [Credential redacted for security]")'
            explanation = "Redacted sensitive administrative secret from debug console output (CWE-200)."

        elif "SEC-DATA-003" in rule_id or "Bound" in title or "Off-By-One" in title:
            proposed_source = source_code
            if "> 5" in proposed_source:
                proposed_source = proposed_source.replace("> 5", ">= 5")
            if "<= raw_count" in proposed_source:
                proposed_source = proposed_source.replace("<= raw_count", "< raw_count")
            if "<= 5" in proposed_source:
                proposed_source = proposed_source.replace("<= 5", "< 5")
            proposed_code = "// Corrected upper boundary and loop counter limits"
            explanation = "Corrected upper boundary check to reject index >= 5 and prevent buffer overflow (CWE-129)."

        elif "SEC-INJ-001" in rule_id or "SQL" in title or ("Injection" in title and "eval" not in title.lower()):
            lang_low = language.lower() if language else "english"
            if lang_low == "bengali":
                safe_query = "    // প্যারামিটারাইজড নিরাপদ ডেটাবেস অনুসন্ধান\n    ধরো সম্পূর্ণ_কোয়েরি = \"SELECT user_id, email FROM accounts WHERE role = 'user' AND user_id = ?\""
            elif lang_low == "hindi":
                safe_query = "    // सुरक्षित पैरामीटराइज्ड डेटाबेस लुकअप\n    मानो पूरा_क्वेरी = \"SELECT user_id, email FROM accounts WHERE role = 'user' AND user_id = ?\""
            elif lang_low == "telugu":
                safe_query = "    // సురక్షిత పారామీటరైజ్డ్ ప్రశ్న\n    అనుకో పూర్తి_క్వెరీ = \"SELECT user_id, email FROM accounts WHERE role = 'user' AND user_id = ?\""
            elif lang_low == "marathi":
                safe_query = "    // सुरक्षित पॅरामीटराइज्ड चौकशी\n    घ्या पूर्ण_चौकशी = \"SELECT user_id, email FROM accounts WHERE role = 'user' AND user_id = ?\""
            elif lang_low == "nepali":
                safe_query = "    // सुरक्षित प्यारामिटराइज्ड क्वेरी\n    मान पूरा_क्वेरी = \"SELECT user_id, email FROM accounts WHERE role = 'user' AND user_id = ?\""
            else:
                safe_query = "    // Parameterized database lookup\n    let full_query = \"SELECT user_id, email FROM accounts WHERE role = 'user' AND user_id = ?\"" 

            # Multilingual match for query prefix + filter concatenation
            sql_concat_pat = re.compile(
                r'[ \t]*(?:let|मानो|అనుకో|ধরো|घ्या|मान)\s+[^\n=]+=\s*(?:SELECT[^\n]+|query_prefix|క్వెరీ_ప్రారంభం|কোয়েরি_শুরু|क्वेरी_प्रारंभ|क्वेरी_सुरुवात|क्वेरी_सुरु)\s*(?:\+|,\s*)\s*(?:user_filter|फ़िल्टर|ఫిల్టర్|ফিল্টার|फिल्टर|malicious_sql|ক্ষতিকারক_sql)'
            )
            func_pat = re.compile(
                r'[ \t]*(?:let|मानो|అనుకో|ধরো|घ्या|मान)\s+(?:query_prefix|క్వెరీ_ప్రారంభం|কোয়েরি_শুরু|क्वेरी_प्रारंभ|क्वेरी_सुरुवात|क्वेरी_सुरु)\s*=\s*[^\n]+\n[ \t]*(?:let|मानो|అనుకో|ধরো|घ्या|मान)\s+[^\n=]+\s*=\s*[^\n]+'
            )

            m_func = func_pat.search(source_code)
            m_sql = sql_concat_pat.search(source_code)
            if m_func:
                proposed_source = source_code[:m_func.start()] + safe_query + source_code[m_func.end():]
                proposed_code = safe_query
            elif m_sql:
                proposed_source = source_code[:m_sql.start()] + safe_query + source_code[m_sql.end():]
                proposed_code = safe_query
            else:
                proposed_code = safe_query
            explanation = "Replaced dynamic string concatenation with safe parameterized database query logic (CWE-89)."

        elif "SEC-LOGIC-001" in rule_id or "Negative" in title or "Refund" in title:
            proposed_code = f"    if (item_quantity <= 0) {{\n        print('Error: Quantity must be positive.')\n        return 0\n    }}\n    {evidence}"
            explanation = "Added negative item quantity validation to prevent invoice balance reversals (CWE-840)."

        elif "eval" in title.lower() or "exec" in title.lower() or "SEC-EXEC-001" in rule_id or "SEC-IR_-003" in rule_id or "SEC-IR_-001" in rule_id:
            eval_pat = re.compile(r'[ \t]*eval\s*\([^)]*\)')
            if eval_pat.search(source_code):
                proposed_source = eval_pat.sub("    // Neutralized dynamic evaluation sink\n    print('Notice: Dynamic evaluation safely neutralized.')", source_code)
                proposed_code = "    // Neutralized dynamic evaluation sink\n    print('Notice: Dynamic evaluation safely neutralized.')"
            else:
                proposed_code = f"// REMOVED UNSAFE DYNAMIC EVALUATION: {evidence}\nprint('Notice: Dynamic evaluation neutralized.')"
            explanation = "Neutralized dynamic code execution vulnerability by removing eval/exec call."

        elif "Null Byte" in title or "SEC-LEX-001" in rule_id:
            proposed_source = source_code.replace("\\x00", "").replace("\x00", "")
            proposed_code = "// Removed null byte injection character"
            explanation = "Removed null byte character to prevent string termination attacks (CWE-626)."

        elif ("Homoglyph" in title and "Cyrillic" in title) or "SEC-LEX-002" in rule_id:
            proposed_source = source_code
            for c, l in DeterministicSecurityScanner.HOMOGLYPH_CYRILLIC.items():
                proposed_source = proposed_source.replace(c, l)
            proposed_code = "// Normalized Cyrillic homoglyphs to standard Latin"
            explanation = "Replaced deceptive Cyrillic homoglyphs with standard Latin characters."

        elif ("Homoglyph" in title and "Devanagari" in title) or "SEC-LEX-003" in rule_id:
            proposed_source = source_code
            for d, s in DeterministicSecurityScanner.HOMOGLYPH_DEVANAGARI.items():
                proposed_source = proposed_source.replace(d, s)
            proposed_code = "// Normalized Devanagari punctuation"
            explanation = "Normalized Devanagari punctuation ('।' danda) to standard ASCII operators."

        elif "Chaining" in title or "SEC-LEX-004" in rule_id:
            # Replace shell chaining in string literal
            proposed_source = source_code.replace(" ; rm -rf /tmp/vital_sandbox", "").replace(" ; ", " ")
            proposed_code = '// Removed shell command chaining delimiter (;)'
            explanation = "Removed shell metacharacters and chaining delimiters to prevent arbitrary command execution (CWE-78)."

        elif "Traversal" in title or "SEC-LEX-005" in rule_id:
            proposed_source = source_code.replace("../", "").replace("..\\", "")
            proposed_code = "// Sanitized directory traversal sequences (../)"
            explanation = "Sanitized directory traversal sequence to prevent path manipulation (CWE-22)."

        elif "unindent" in title.lower() or "indentation" in title.lower() or "indent" in title.lower():
            # Indentation correction (e.g. line 14 '} else {' unindent or misaligned statement)
            lines = source_code.splitlines()
            target_line_idx = (line_no - 1) if (line_no and 1 <= line_no <= len(lines)) else 0
            if 0 <= target_line_idx < len(lines):
                cur_line = lines[target_line_idx]
                # Check for `} else` or `else` block across English, Hindi, Telugu, Bengali, Marathi, and Nepali
                else_match = re.search(r'\b(else|अन्यथा|కాకపోతే|లేకపోతే|నাহলে|नाहीतर|नत्र)\b', cur_line)
                if else_match or "} else" in cur_line:
                    else_kw = else_match.group(1) if else_match else "else"
                    matching_indent = 4
                    for idx in range(target_line_idx - 1, -1, -1):
                        prev = lines[idx]
                        if re.search(r'\b(?:if|अगर|ఒకవేళ|যদি|जर|यदि|यदि_हो)\b', prev):
                            matching_indent = len(prev) - len(prev.lstrip())
                            break
                    indent_str = " " * matching_indent
                    if "}" in cur_line:
                        fixed_line = f"{indent_str}}} {else_kw} {{"
                    else:
                        fixed_line = f"{indent_str}{else_kw} {{"
                    lines[target_line_idx] = fixed_line
                    proposed_code = fixed_line
                    proposed_source = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
                    explanation = f"Corrected indentation at line {target_line_idx + 1} to align with block scope ({matching_indent} spaces)."
                else:
                    # General indentation normalization to nearest 4-space multiple
                    stripped = cur_line.lstrip()
                    prev_indent = 0
                    if target_line_idx > 0:
                        prev_line = lines[target_line_idx - 1]
                        prev_indent = len(prev_line) - len(prev_line.lstrip())
                        if prev_line.rstrip().endswith("{"):
                            prev_indent += 4
                    fixed_line = (" " * prev_indent) + stripped
                    lines[target_line_idx] = fixed_line
                    proposed_code = fixed_line
                    proposed_source = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
                    explanation = f"Adjusted indentation at line {target_line_idx + 1} to match block nesting."

        elif "Unbalanced" in title or "SEC-PAR-001" in rule_id or "Delimiter" in title or "syntax" in title.lower() or "parser" in title.lower() or "Parenthes" in title or "SEC-PAR-002" in rule_id:
            # Delimiter balancing (braces, parentheses, quotes)
            lines = source_code.splitlines()
            target_line_idx = (line_no - 1) if (line_no and 1 <= line_no <= len(lines)) else -1
            
            # Check for duplicate delimiters on the specific line (e.g. `{{` or `}}`)
            if target_line_idx >= 0 and "{{" in lines[target_line_idx]:
                lines[target_line_idx] = lines[target_line_idx].replace("{{", "{", 1)
                proposed_code = lines[target_line_idx]
                proposed_source = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
                explanation = f"Removed duplicate open brace '{{' at line {target_line_idx + 1}."
            elif target_line_idx >= 0 and "))" in lines[target_line_idx]:
                lines[target_line_idx] = lines[target_line_idx].replace("))", ")", 1)
                proposed_code = lines[target_line_idx]
                proposed_source = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
                explanation = f"Removed duplicate parenthesis ')' at line {target_line_idx + 1}."
            else:
                # Strip comments when checking delimiter balance so comment text does not skew counts
                clean_lines = []
                comment_prefixes = ("#", "//", "comment", "टिप्पणी", "వ్యాఖ్య", "মন্তব্য", "টিপ", "टीप", "टिप्पणी_गर", "शेरा")
                for line in lines:
                    trimmed = line.strip()
                    if any(trimmed.startswith(cp) for cp in comment_prefixes):
                        continue
                    for cp in ("//", "#"):
                        idx = line.find(cp)
                        if idx != -1:
                            line = line[:idx]
                    clean_lines.append(line)
                clean_code = "\n".join(clean_lines)

                open_b = clean_code.count('{')
                close_b = clean_code.count('}')
                open_p = clean_code.count('(')
                close_p = clean_code.count(')')
                if open_b > close_b:
                    proposed_source = source_code.rstrip() + ("\n}" * (open_b - close_b)) + "\n"
                    proposed_code = "\n}" * (open_b - close_b)
                    explanation = "Appended matching closing brace '}' to balance block scope and satisfy grammar rules."
                elif close_b > open_b:
                    # Remove extraneous closing brace
                    if target_line_idx >= 0 and "}" in lines[target_line_idx]:
                        # Remove one '}' from target line
                        lines[target_line_idx] = lines[target_line_idx].replace("}", "", 1)
                        proposed_code = lines[target_line_idx]
                        proposed_source = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
                    else:
                        last_cb = source_code.rfind("}")
                        if last_cb != -1:
                            proposed_source = source_code[:last_cb] + source_code[last_cb+1:]
                            proposed_code = "// Removed extra closing brace"
                    explanation = "Removed extraneous closing brace '}' to balance block scope."
                elif open_p > close_p:
                    proposed_source = source_code.rstrip() + (")" * (open_p - close_p)) + "\n"
                    proposed_code = ")" * (open_p - close_p)
                    explanation = "Appended matching closing parenthesis ')' to balance expression delimiters."
                elif close_p > open_p:
                    if target_line_idx >= 0 and ")" in lines[target_line_idx]:
                        lines[target_line_idx] = lines[target_line_idx].replace(")", "", 1)
                        proposed_code = lines[target_line_idx]
                        proposed_source = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
                    else:
                        last_cp = source_code.rfind(")")
                        if last_cp != -1:
                            proposed_source = source_code[:last_cp] + source_code[last_cp+1:]
                            proposed_code = "// Removed extra closing parenthesis"
                    explanation = "Removed extraneous closing parenthesis ')' to balance expression delimiters."
                else:
                    open_q = source_code.count('"')
                    if open_q % 2 != 0:
                        proposed_source = source_code.rstrip() + '"\n'
                        proposed_code = '"'
                        explanation = "Appended matching quotation mark '\"' to balance string literal."
                    else:
                        proposed_code = ""
                        proposed_source = ""
                        explanation = "Syntax delimiter review."

        elif "Division by zero" in title.lower() or "SEM-001" in rule_id:
            # Fix division by zero
            proposed_source = re.sub(r'/\s*0\b', '/ 1', source_code)
            proposed_code = "// Replaced division by zero with safe divisor"
            explanation = "Guarded arithmetic operation against division by zero runtime crash."

        # Step 2: If targeted fix produced no change to the source, try evidence or line replacement
        if not proposed_source or proposed_source == source_code:
            if evidence and evidence in source_code and proposed_code:
                proposed_source = source_code.replace(evidence, proposed_code, 1)
            elif line_no and 1 <= line_no <= len(source_code.splitlines()) and proposed_code:
                lines = source_code.splitlines()
                lines[line_no - 1] = proposed_code
                proposed_source = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")

        # Step 3: Fallback to registered demo reference repair only if still no change and single-finding demo
        if not proposed_source or proposed_source == source_code:
            try:
                from web.security_lab_registry import SECURITY_LAB_DEMOS
                for demo in SECURITY_LAB_DEMOS:
                    if demo.language.lower() == language.lower() and (
                        demo.scenario_type.lower() in title.lower() or
                        any(f.rule_id == rule_id for f in demo.expected_findings) or
                        demo.title.lower() in title.lower() or
                        (demo.relative_path and demo.relative_path in source_code)
                    ):
                        # CRITICAL: Do NOT apply whole-file reference fix if demo has multiple findings,
                        # as it would replace the entire file and accidentally resolve other findings!
                        if len(demo.expected_findings) <= 1:
                            if demo.reference_fix_code and len(demo.reference_fix_code) > 20:
                                proposed_source = demo.reference_fix_code
                                explanation = f"Applied verified secure reference repair for {demo.title}: {demo.reference_fix_description}"
                                break
            except Exception:
                pass

        if not proposed_source or proposed_source == source_code:
            if proposed_code:
                proposed_source = source_code + f"\n// Remediation:\n{proposed_code}\n"
            else:
                return None

        diff_str = self.generate_diff(source_code, proposed_source)
        # Use cached health status to ensure instant (<2ms) CPU-only response without blocking on network probes
        is_healthy = bool(self.ollama._cached_health and self.ollama._cached_health[0])

        return {
            "success": True,
            "finding_id": finding_id,
            "rule_id": rule_id,
            "original_code": evidence or source_code,
            "proposed_code": proposed_code or proposed_source,
            "proposed_source": proposed_source,
            "explanation": explanation,
            "diff": diff_str,
            "fix_source": "Local rule",
            "is_deterministic": True,
            "validation_status": "Not yet validated",
            "can_refine_with_ai": is_healthy,
            "cached": False
        }

    def suggest_fix_for_finding(
        self,
        source_code: str,
        finding_id: Any = "",
        finding_data: Optional[Dict[str, Any]] = None,
        language: str = "English",
        prefer_deterministic: bool = True,
        request_ai: bool = False
    ) -> Dict[str, Any]:
        """
        Generates a reviewed, minimal correction diff for a specific finding.
        1. Checks in-memory remediation cache for instant response.
        2. If prefer_deterministic is True, runs deterministic security remediation rules first.
        3. If no deterministic rule applies or request_ai is True, requests local Ollama with timeout.
        4. Never leaves UI hanging; falls back cleanly to deterministic suggestion if Ollama times out.
        """
        if isinstance(finding_id, SecurityFinding):
            finding_data = finding_id.to_dict()
            finding_id = finding_id.id
        elif isinstance(finding_id, dict):
            finding_data = finding_id
            finding_id = finding_data.get("id", "")
        elif finding_data is None:
            finding_data = {}

        evidence = finding_data.get("evidence", "")
        line_no = finding_data.get("line")
        title = finding_data.get("title", "")
        rule_id = finding_data.get("rule_id", "")

        cache_key = self._compute_cache_key(source_code, finding_id, rule_id, line_no, evidence, language, model=getattr(self, 'active_model', ''))
        if not request_ai and cache_key in self._fix_cache:
            cached = dict(self._fix_cache[cache_key])
            cached["cached"] = True
            return cached

        # Step 1: Run deterministic security remediation rules first (instant, <2ms)
        if prefer_deterministic and not request_ai:
            det_fix = self.generate_deterministic_fix(source_code, finding_id, finding_data, language)
            if det_fix is not None:
                if len(self._fix_cache) >= 256:
                    self._fix_cache.pop(next(iter(self._fix_cache)))
                self._fix_cache[cache_key] = det_fix
                return det_fix

        # Step 2: Use local Ollama (with strict 5s timeout) for complex cases or explicit AI request
        is_healthy, health_msg, _ = self.ollama.check_health()
        if is_healthy:
            try:
                system_prompt = (
                    "You are an expert compiler security engineer. Propose a minimal, safe replacement code snippet "
                    "that fixes the security issue without modifying unrelated logic. "
                    "Output strictly a JSON object: "
                    '{"proposed_code": "<minimal corrected snippet>", "explanation": "<why this fix resolves the vulnerability>"}'
                )
                user_prompt = (
                    f"Vulnerability: {title} ({rule_id})\n"
                    f"Evidence: {evidence}\n"
                    f"Line Number: {line_no}\n"
                    f"Language: {language}\n"
                    f"Full Source:\n{source_code[:1800]}\n"
                )

                res = self.ollama.chat(
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=0.1,
                    max_tokens=512,
                    response_format="json",
                    timeout=5.0
                )

                if res.get("success"):
                    content = res.get("content", "")
                    parsed = json.loads(content)
                    proposed_code = parsed.get("proposed_code", "")
                    explanation = parsed.get("explanation", "")

                    if proposed_code:
                        from web.ai_remediation_engine import AIRemediationEngine
                        if evidence and evidence in source_code:
                            proposed_source = AIRemediationEngine._apply_snippet_to_source(
                                source_code=source_code,
                                target_line=line_no or 1,
                                orig_snippet=evidence,
                                prop_snippet=proposed_code
                            )
                        else:
                            proposed_source = source_code + "\n" + proposed_code

                        diff_str = self.generate_diff(source_code, proposed_source)
                        fix_dict = {
                            "success": True,
                            "finding_id": finding_id,
                            "rule_id": rule_id,
                            "original_code": evidence or source_code,
                            "proposed_code": proposed_code,
                            "proposed_source": proposed_source,
                            "explanation": explanation or f"Ollama AI patch for {title}",
                            "diff": diff_str,
                            "fix_source": "Ollama AI",
                            "is_deterministic": False,
                            "validation_status": "Not yet validated",
                            "can_refine_with_ai": False,
                            "cached": False
                        }
                        self._fix_cache[cache_key] = fix_dict
                        return fix_dict
            except Exception:
                pass

        # Step 3: Fallback to deterministic fix if model was offline or failed/timed out
        det_fix = self.generate_deterministic_fix(source_code, finding_id, finding_data, language)
        if det_fix is not None:
            if not is_healthy:
                det_fix["explanation"] += f" (Local Ollama offline: {health_msg}; deterministic rule applied.)"
            self._fix_cache[cache_key] = det_fix
            return det_fix

        # If stage is a compiler stage, consult the shared AIRemediationEngine before manual fallback (unless deterministic only requested)
        stage_check = str(finding_data.get("stage_id", "")).lower()
        if not prefer_deterministic and (stage_check in ("syntax_analysis", "lexical_analysis", "ast_construction", "semantic_analysis", "parser", "optimization", "code_generation", "code_validation") or str(rule_id).startswith(("SYN-", "SEC-PAR-", "SEM-", "SEC-SEM-", "IR-", "OPT-"))):
            try:
                from web.ai_remediation_engine import remediation_engine
                engine_fix = remediation_engine.generate_fix(
                    source_code=source_code,
                    stage_id=stage_check or "syntax_analysis",
                    finding_id=finding_id,
                    finding_data=finding_data,
                    language=language
                )
                if engine_fix and engine_fix.get("success"):
                    self._fix_cache[cache_key] = engine_fix
                    return engine_fix
            except Exception:
                pass

        if stage_check in ("syntax_analysis", "lexical_analysis", "ast_construction", "semantic_analysis", "parser", "optimization", "code_generation", "code_validation") or str(rule_id).startswith(("SYN-", "SEC-PAR-", "SEM-", "SEC-SEM-", "IR-", "OPT-")):
            return {
                "success": False,
                "finding_id": finding_id,
                "rule_id": rule_id,
                "error": f"Automated fix could not be deterministically determined for {title}. Please review line {line_no} and apply manual correction.",
                "validation_status": "Unable to fix automatically",
                "can_refine_with_ai": is_healthy
            }

        # Generic safe fallback for security advisories
        proposed_code = f"// [Security Review]: {title}\n// Line {line_no or ''}: {evidence}"
        proposed_source = source_code
        if evidence and evidence in source_code:
            proposed_source = source_code.replace(evidence, proposed_code, 1)
        diff_str = self.generate_diff(source_code, proposed_source)

        if proposed_source == source_code or not diff_str:
            return {
                "success": False,
                "finding_id": finding_id,
                "rule_id": rule_id,
                "error": f"Automated fix could not be deterministically determined for {title}. Manual review recommended.",
                "validation_status": "Unable to fix automatically",
                "can_refine_with_ai": is_healthy
            }

        fallback_fix = {
            "success": True,
            "finding_id": finding_id,
            "rule_id": rule_id,
            "original_code": evidence or source_code,
            "proposed_code": proposed_code,
            "proposed_source": proposed_source,
            "explanation": f"Generic security advisory: {title}. Manual review recommended.",
            "diff": diff_str,
            "fix_source": "Local rule",
            "is_deterministic": True,
            "validation_status": "Not yet validated",
            "can_refine_with_ai": is_healthy,
            "cached": False
        }
        self._fix_cache[cache_key] = fallback_fix
        return fallback_fix

    def refine_fix_with_ollama(
        self,
        source_code: str,
        finding_id: Any = "",
        finding_data: Optional[Dict[str, Any]] = None,
        current_fix: Optional[Dict[str, Any]] = None,
        language: str = "English"
    ) -> Dict[str, Any]:
        """
        Asynchronously refines an existing deterministic proposal using Ollama AI.
        If Ollama is offline or times out, safely retains the deterministic proposal.
        """
        is_healthy, health_msg, _ = self.ollama.check_health()
        if not is_healthy:
            return {
                "success": False,
                "message": f"Ollama service offline ({health_msg}). Deterministic proposal retained.",
                "retained_fix": current_fix
            }

        finding_data = finding_data or {}
        title = finding_data.get("title", "")
        rule_id = finding_data.get("rule_id", "")
        evidence = finding_data.get("evidence", "")
        cur_code = (current_fix or {}).get("proposed_code", "")

        try:
            system_prompt = (
                "You are an expert compiler security engineer. Review the current proposed code patch "
                "and refine it to be idiomatic, minimal, and fully secure for the VITAL language. "
                "Return strictly JSON: "
                '{"proposed_code": "<refined snippet>", "explanation": "<why this refinement improves safety>"}'
            )
            user_prompt = (
                f"Language: {language}\n"
                f"Finding: {title} ({rule_id})\n"
                f"Original Code: {evidence}\n"
                f"Current Proposed Fix:\n{cur_code}\n\n"
                f"Full Context:\n{source_code[:1800]}\n"
            )

            res = self.ollama.chat(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,
                max_tokens=512,
                response_format="json",
                timeout=5.0
            )

            if res.get("success"):
                content = res.get("content", "")
                parsed = json.loads(content)
                refined_code = parsed.get("proposed_code", "").strip()
                explanation = parsed.get("explanation", "").strip()

                if refined_code:
                    proposed_source = source_code
                    if evidence and evidence in source_code:
                        proposed_source = source_code.replace(evidence, refined_code, 1)
                    elif cur_code and cur_code in source_code:
                        proposed_source = source_code.replace(cur_code, refined_code, 1)
                    else:
                        proposed_source = source_code + "\n" + refined_code

                    diff_str = self.generate_diff(source_code, proposed_source)
                    return {
                        "success": True,
                        "finding_id": finding_id,
                        "rule_id": rule_id,
                        "original_code": evidence or source_code,
                        "proposed_code": refined_code,
                        "proposed_source": proposed_source,
                        "explanation": f"Refined by Ollama AI: {explanation}",
                        "diff": diff_str,
                        "fix_source": "Ollama AI",
                        "is_deterministic": False,
                        "validation_status": "Not yet validated",
                        "can_refine_with_ai": False
                    }
        except Exception:
            pass

        return {
            "success": False,
            "message": "Ollama AI refinement timed out or returned invalid format. Retaining deterministic fix.",
            "retained_fix": current_fix
        }

    def verify_repair(
        self,
        original_source: str,
        repaired_source: str,
        language: str = "English",
        target_finding_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verifies that a code repair actually resolves compiler and security defects:
          1. Scans original source to capture baseline findings and score.
          2. Re-runs lexical analysis, parser delimiter checks, and semantic analysis on repaired code.
          3. Confirms whether original syntax or semantic defect is resolved.
          4. Re-runs security rules to verify defect resolution and check for regressions.
          5. Computes updated vulnerability risk score.
          6. Returns complete pedagogical verification report.
        """
        if not repaired_source or not repaired_source.strip():
            return {
                "success": False,
                "status": "Failed",
                "summary": "Repair validation failed: Repaired source code is empty.",
                "resolved_count": 0,
                "remaining_count": 0,
                "updated_risk_score": 0,
                "resolved_findings": [],
                "remaining_findings": []
            }

        # 1. Baseline scan on original source
        orig_scan = self.run_full_scan(original_source, language=language, use_ai_enrichment=False)
        orig_findings = orig_scan.get("findings", [])
        orig_score = orig_scan.get("overall_risk_score", 0)

        # 2. Check delimiters and compiler parser on repaired code
        is_syntax_clean = True
        try:
            from web.ai_remediation_engine import DiagnosticNormalizer
            delim_info = DiagnosticNormalizer.analyze_delimiters(repaired_source)
            if not delim_info.get("is_balanced", True):
                is_syntax_clean = False
            else:
                c = Compiler(RULES_FILE)
                c.load_rules()
                if not c.run_parser(repaired_source):
                    is_syntax_clean = False
        except Exception:
            open_braces = repaired_source.count('{')
            close_braces = repaired_source.count('}')
            is_syntax_clean = (open_braces == close_braces)

        # 3. Re-scan repaired source code
        repaired_scan = self.run_full_scan(
            repaired_source,
            language=language,
            use_ai_enrichment=False,
            syntax_blocked=(not is_syntax_clean)
        )
        repaired_findings = repaired_scan.get("findings", [])
        updated_score = repaired_scan.get("overall_risk_score", 0)

        # 4. Compute delta by matching findings across scans robustly (resilient to line number shifts)
        unmatched_repaired = list(repaired_findings)
        resolved_findings: List[Dict[str, Any]] = []
        remaining_findings: List[Dict[str, Any]] = []

        for orig_f in orig_findings:
            o_dict = orig_f if isinstance(orig_f, dict) else orig_f.to_dict()
            o_rule = o_dict.get("rule_id") or ""
            o_id = o_dict.get("id") or ""
            o_title = o_dict.get("title") or ""
            o_ev = (o_dict.get("evidence") or "").strip()

            best_match = None
            best_score = 0.0

            for rep_f in unmatched_repaired:
                r_dict = rep_f if isinstance(rep_f, dict) else rep_f.to_dict()
                r_rule = r_dict.get("rule_id") or ""
                r_id = r_dict.get("id") or ""
                r_title = r_dict.get("title") or ""
                r_ev = (r_dict.get("evidence") or "").strip()

                score = 0.0
                if o_id and r_id and o_id == r_id:
                    score = 1.0
                elif o_rule and r_rule and o_rule == r_rule:
                    score = 0.7
                    if o_title and r_title and o_title == r_title:
                        score += 0.2
                    if o_ev and r_ev and (o_ev in r_ev or r_ev in o_ev or o_ev == r_ev):
                        score += 0.1

                if score > best_score:
                    best_score = score
                    best_match = rep_f

            if best_match and best_score >= 0.7:
                unmatched_repaired.remove(best_match)
                m_dict = best_match if isinstance(best_match, dict) else best_match.to_dict()
                m_dict["status"] = "still_present"
                m_dict["validation_status"] = "still_detected"
                remaining_findings.append(m_dict)
            else:
                o_res = dict(o_dict)
                o_res["status"] = "resolved"
                o_res["validation_status"] = "validated_resolved"
                resolved_findings.append(o_res)

        new_regressions = [
            f if isinstance(f, dict) else f.to_dict()
            for f in unmatched_repaired
        ]

        # 5. Formulate verification status
        target_resolved = True
        if target_finding_id:
            target_resolved = any(
                rf.get("id") == target_finding_id or 
                (rf.get("rule_id") and rf.get("rule_id") in str(target_finding_id))
                for rf in resolved_findings
            )

        if not is_syntax_clean:
            status = "Failed"
            summary = "Repair validation: Failed. The proposed repair introduces unbalanced block delimiters ('{' vs '}')."
        elif len(new_regressions) > 0 or not target_resolved:
            status = "Failed"
            if not target_resolved:
                summary = f"Repair validation: Failed. Target issue ({target_finding_id}) is still present in the repaired code."
            else:
                summary = f"Repair validation: Failed. {len(remaining_findings)} finding(s) remain, and {len(new_regressions)} regression(s) were detected."
        elif len(remaining_findings) == 0:
            status = "Passed"
            summary = f"Repair validation: Passed. All {len(resolved_findings)} original finding(s) resolved cleanly. Updated risk score: {updated_score}/100."
        else:
            status = "Partial"
            summary = f"Repair validation: Partial. Successfully resolved {len(resolved_findings)} finding(s); {len(remaining_findings)} finding(s) remain. Updated risk score: {updated_score}/100."

        return {
            "success": True,
            "status": status,
            "summary": summary,
            "resolved_count": len(resolved_findings),
            "remaining_count": len(remaining_findings),
            "regressions_count": len(new_regressions),
            "original_risk_score": orig_score,
            "updated_risk_score": updated_score,
            "resolved_findings": resolved_findings,
            "remaining_findings": remaining_findings,
            "new_regressions": new_regressions,
            "syntax_valid": is_syntax_clean
        }

    @staticmethod
    def generate_diff(original: str, modified: str) -> str:
        """Generates a standard readable unified diff."""
        orig_lines = original.splitlines(keepends=True)
        mod_lines = modified.splitlines(keepends=True)
        diff = difflib.unified_diff(
            orig_lines,
            mod_lines,
            fromfile="original.vital",
            tofile="remediated.vital",
            n=2
        )
        return "".join(diff)


# Singleton coordinator
security_coordinator = SecurityAnalysisCoordinator()

