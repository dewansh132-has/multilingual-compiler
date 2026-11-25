# -*- coding: utf-8 -*-
"""
web/gate_policy.py — Centralized Security Gating Policy Configuration for Stages 11 and 12.

Defines:
- GatePolicy: Configurable threshold object controlling deterministic SAST (Stage 11)
  and AI security analysis (Stage 12).
- Security decision rules (BLOCK vs ALLOW).
- Severity mappings and confidence thresholds.
- Finding normalization ensuring {id, cwe, severity, line, column, message, evidence, source_stage}.
- Quota protection: run_ai_even_if_sast_fails flag.
- Educational override support for sandboxed execution.
"""

import os
import re
from dataclasses import dataclass, field
from typing import Dict, Any, List, Set, Tuple, Optional

# Standard CWE Mappings for VITAL Security Rules
RULE_CWE_MAP = {
    "SEC-LEX-001": "CWE-626",   # Null Byte Interaction
    "SEC-LEX-002": "CWE-78",    # Command Injection / Shell Metacharacters
    "SEC-LEX-003": "CWE-134",   # Format String Injection
    "SEC-LEX-004": "CWE-1036",  # Multi-lingual Homoglyph / Trojan Source
    "SEC-LEX-005": "CWE-22",    # Path Traversal
    "SEC-LEX-006": "CWE-798",   # Hardcoded Credentials / Secrets
    "SEC-LEX-007": "CWE-95",    # Improper Neutralization of Directives in Dynamically Evaluated Code (Eval)
    "SEC-PAR-001": "CWE-20",    # Unbalanced Braces / Delimiter Syntax Error
    "SEC-PAR-002": "CWE-20",    # Unbalanced Parentheses
    "SEC-AST-001": "CWE-798",   # Hardcoded Cryptographic Key / API Secret
    "SEC-AST-002": "CWE-338",   # Use of Cryptographically Weak PRNG
    "SEC-AST-003": "CWE-78",    # Unsanitized Subprocess Execution
    "SEC-AST-004": "CWE-732",   # Insecure File Permissions
    "SEC-SEM-001": "CWE-639",   # Missing Object Level Access Control / Undeclared Identifier
    "SEC-SEM-002": "CWE-285",   # Improper Authorization / Selective State Check Bypass
    "SEC-INJ-001": "CWE-89",    # SQL / Query Injection
    "SEC-INFO-001": "CWE-200",  # Exposure of Sensitive Information in Debug Logs
    "SEC-LOGIC-001": "CWE-840", # Business Logic Reversal / Calculation Defect
    "SEC-OOB-001": "CWE-129",   # Improper Validation of Array Index
    "SEM-001": "CWE-369",       # Divide By Zero
    "SEC-AUTH-001": "CWE-639",  # IDOR / Broken Object-Level Authorization
    "SEC-AUTH-003": "CWE-285",  # Improper Authorization / State Check Bypass
    "SEC-DATA-001": "CWE-798",  # Hardcoded Credentials / Secrets
    "SEC-DATA-002": "CWE-200",  # Exposure of Sensitive Information in Debug Logs
    "SEC-DATA-003": "CWE-129",  # Improper Validation of Array Index
    "SEC-DATA-004": "CWE-129",  # Improper Validation of Array Index
    "SEC-IR-001": "CWE-94",     # Dynamic Code Evaluation (eval)
    "SEC-IR-002": "CWE-94",     # Arbitrary Code Execution (exec)
    "SEC-IR-003": "CWE-94",     # Dynamic AST Compilation (compile)
    "SEC-IR-004": "CWE-94",     # Dynamic Module Import (__import__)
    "SEC-IR-005": "CWE-78",     # OS Command Execution (system)
    "SEC-IR-006": "CWE-78",     # Process Pipe Execution (popen)
    "SEC-IR-007": "CWE-78",     # Process Spawning (spawn)
    "SEC-IR-010": "CWE-78",     # Subprocess Module Invocation
    "SEC-IR-016": "CWE-502",    # Insecure Deserialization
    "SEC-RUN-001": "CWE-78",    # Command Execution
    "SEC-RUN-002": "CWE-78",    # Command Execution
    "SEC-EVAL-003": "CWE-94",   # Code Injection
    "SEC-EXEC-001": "CWE-94",   # Code Execution
    "SEC-IDOR-001": "CWE-639",  # IDOR
    "SEC-PWD-002": "CWE-798",   # Hardcoded Credentials
    "SEC-TIME-004": "CWE-208",  # Timing Discrepancy
}


@dataclass
class GatePolicy:
    """Configurable security gating policy thresholds for Stages 11 and 12."""

    # Stage 11 (Deterministic SAST) thresholds
    stage11_blocking_severities: Set[str] = field(default_factory=lambda: {"CRITICAL", "HIGH"})
    stage11_warning_severities: Set[str] = field(default_factory=lambda: {"MEDIUM", "LOW"})

    # Stage 12 (AI Security Analysis) thresholds
    stage12_blocking_severities: Set[str] = field(default_factory=lambda: {"CRITICAL", "HIGH"})
    stage12_warning_severities: Set[str] = field(default_factory=lambda: {"MEDIUM", "LOW"})
    stage12_min_blocking_confidence: float = 0.6
    stage12_timeout_seconds: float = 20.0

    # Pipeline optimization and quota protection
    # If Stage 11 blocks, do NOT call Gemini API for Stage 12 (saves quota; marks Stage 12 blocked by Stage 11)
    run_ai_even_if_sast_fails: bool = False

    # Educational sandbox override
    allow_sandbox_override: bool = True

    def evaluate_stage11(self, findings: List[Dict[str, Any]]) -> Tuple[str, str]:
        """
        Evaluates Stage 11 deterministic findings.
        Returns (stage_status, gate_decision):
        - any CRITICAL or HIGH finding -> status 'failed', gate decision 'BLOCK'
        - only MEDIUM or LOW findings -> status 'warning', gate decision 'ALLOW'
        - no findings -> status 'passed', gate decision 'ALLOW'
        """
        if not findings:
            return "passed", "ALLOW"

        for f in findings:
            sev = str(f.get("severity", "")).upper()
            if sev in self.stage11_blocking_severities:
                return "failed", "BLOCK"

        for f in findings:
            sev = str(f.get("severity", "")).upper()
            if sev in self.stage11_warning_severities:
                return "warning", "ALLOW"

        return "passed", "ALLOW"

    def evaluate_stage12(
        self,
        ai_findings: List[Dict[str, Any]],
        stage11_findings: Optional[List[Dict[str, Any]]] = None
    ) -> Tuple[str, str]:
        """
        Evaluates Stage 12 AI findings.
        Rules:
        - Only findings with confidence >= stage12_min_blocking_confidence (default 0.6)
          can trigger a BLOCK.
        - AI findings must NEVER downgrade a Stage 11 finding.
        - Returns (stage_status, gate_decision).
        """
        # Rule: AI findings must never downgrade a Stage 11 finding
        stage11_blocked = False
        if stage11_findings:
            s11_status, s11_decision = self.evaluate_stage11(stage11_findings)
            if s11_decision == "BLOCK":
                stage11_blocked = True

        if not ai_findings and not stage11_findings:
            return "passed", "ALLOW"

        has_blocking = False
        has_warning = False

        for f in ai_findings:
            sev = str(f.get("severity", "")).upper()
            # Extract confidence (default 1.0 if not specified or confirmed string)
            conf_val = 1.0
            raw_conf = f.get("confidence")
            if isinstance(raw_conf, (int, float)):
                conf_val = float(raw_conf)
            elif isinstance(raw_conf, str):
                try:
                    conf_val = float(raw_conf)
                except ValueError:
                    conf_val = 0.9 if raw_conf.lower() in ("high", "confirmed", "certain") else 0.5

            if sev in self.stage12_blocking_severities:
                if conf_val >= self.stage12_min_blocking_confidence:
                    has_blocking = True
                else:
                    has_warning = True
            elif sev in self.stage12_warning_severities:
                has_warning = True

        if stage11_blocked or has_blocking:
            return "failed", "BLOCK"
        elif has_warning:
            return "warning", "ALLOW"
        return "passed", "ALLOW"

    def should_run_stage12(
        self,
        stage11_decision: str,
        run_ai_toggle: bool
    ) -> Tuple[bool, str, str]:
        """
        Determines whether Stage 12 should run.
        Returns (should_run: bool, target_status: str, reason: str).
        """
        if not run_ai_toggle:
            return False, "skipped", "AI analysis skipped (disabled in toolbar); deterministic analysis used"

        if stage11_decision == "BLOCK" and not self.run_ai_even_if_sast_fails:
            return False, "blocked", "Blocked by Stage 11 (Security Analysis): SAST policy violation detected"

        return True, "running", ""


# Global default policy instance
DEFAULT_GATE_POLICY = GatePolicy()


def extract_cwe_from_text_or_rule(rule_id: str, text: str = "") -> str:
    """Extracts or infers CWE identifier from finding rule_id or text."""
    if rule_id and rule_id in RULE_CWE_MAP:
        return RULE_CWE_MAP[rule_id]
    for k, v in RULE_CWE_MAP.items():
        if k in rule_id:
            return v
    m = re.search(r'\bCWE-(\d+)\b', text, re.IGNORECASE)
    if m:
        return f"CWE-{m.group(1)}"
    lower_text = text.lower()
    if any(k in lower_text for k in ("hardcoded", "secret key", "credential", "password")):
        return "CWE-798"
    if any(k in lower_text for k in ("eval(", "eval()", "dynamic code", "arbitrary code execution")):
        return "CWE-94"
    if any(k in lower_text for k in ("sql", "query injection")):
        return "CWE-89"
    if any(k in lower_text for k in ("path traversal", "../")):
        return "CWE-22"
    if any(k in lower_text for k in ("debug log", "information disclosure", "leaked in console")):
        return "CWE-200"
    if any(k in lower_text for k in ("off-by-one", "bounds", "array index")):
        return "CWE-129"
    return "CWE-699"  # Software Development


def format_security_finding(
    raw_finding: Dict[str, Any],
    source_stage: int,  # 11 or 12
    default_line: int = 1,
    default_column: int = 1
) -> Dict[str, Any]:
    """
    Ensures every security finding conforms strictly to:
    {id, cwe, severity, line, column, message, evidence, source_stage, confidence}
    """
    f_id = (
        raw_finding.get("id")
        or raw_finding.get("rule_id")
        or f"SEC-STAGE{source_stage}-{raw_finding.get('line', default_line)}"
    )
    raw_rule = raw_finding.get("rule_id") or f_id

    # Resolve message/title/evidence
    msg = (
        raw_finding.get("message")
        or raw_finding.get("title")
        or raw_finding.get("explanation")
        or "Security finding detected"
    )
    explanation = raw_finding.get("explanation") or ""
    evidence = (
        raw_finding.get("evidence")
        or raw_finding.get("code_excerpt")
        or raw_finding.get("snippet")
        or ""
    )

    # Resolve CWE
    cwe = raw_finding.get("cwe") or raw_finding.get("cwe_id")
    if not cwe:
        cwe = extract_cwe_from_text_or_rule(raw_rule, f"{msg} {explanation} {evidence}")

    # Resolve severity (uppercase)
    sev = str(raw_finding.get("severity", "MEDIUM")).upper()

    # Resolve line and column
    line = raw_finding.get("line")
    try:
        line = int(line) if line is not None else default_line
    except (ValueError, TypeError):
        line = default_line

    col = raw_finding.get("column")
    try:
        col = int(col) if col is not None else default_column
    except (ValueError, TypeError):
        col = default_column

    # Resolve confidence
    conf = raw_finding.get("confidence", 1.0)
    if isinstance(conf, str):
        try:
            conf = float(conf)
        except ValueError:
            conf = 0.9 if conf.lower() in ("high", "confirmed", "certain") else 0.5

    return {
        "id": f_id,
        "rule_id": raw_rule,
        "cwe": cwe,
        "severity": sev,
        "line": line,
        "column": col,
        "message": msg,
        "evidence": evidence,
        "source_stage": source_stage,
        "confidence": conf,
        "remediation": raw_finding.get("remediation", ""),
        "explanation": explanation
    }
