# -*- coding: utf-8 -*-
"""
web/issue_collector.py — Single Canonical Issue Collection & Accounting System

This module is the SINGLE SOURCE OF TRUTH for every diagnostic, finding, warning,
and error across the VITAL compiler pipeline, Code Health panel, Preflight strip,
and Fix All remediation dialogs.

Rules:
1. Deduplication strictly by (kind, line, column, message).
2. Every count in the UI is derived through counts_by_stage(), counts_by_severity(), or total_fixable().
3. All components (badges, drawer metrics, pills, preflight, health panel, fix dialog) consume
   the exact same collection.
"""

from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Set
import os
import sys
import re
import json
import hashlib

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from web.security_analyzer import DeterministicSecurityScanner, security_coordinator, SecurityFinding
from web.language_context import VitalLanguageIntelligence

# Canonical 14 stage IDs in order
ALL_STAGE_IDS = [
    "source_input",
    "lexical_analysis",
    "syntax_analysis",
    "ast_construction",
    "semantic_analysis",
    "symbol_table",
    "ir_generation",
    "optimization",
    "code_generation",
    "code_validation",
    "security_analysis",
    "ai_security_analysis",
    "sandbox_execution",
    "final_report"
]

# Prohibited / Lookalike characters
try:
    from src.lexer import HOMOGLYPH_MAP
except ImportError:
    try:
        from lexer import HOMOGLYPH_MAP
    except ImportError:
        HOMOGLYPH_MAP = {
            'ः': ':', '।': '.', '॥': '.', '०': '0', 'ऽ': 'S',
            'ঃ': ':', '০': '0', 'ః': ':', '౦': '0',
            'а': 'a', 'е': 'e', 'о': 'o', 'с': 'c', 'р': 'p', 'х': 'x',
            'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H',
            'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
            '“': '"', '”': '"', '‘': "'", '’': "'",
            '\u00A0': ' ', '\u200B': '', '\u200C': '', '\u200D': ''
        }

# Language Rules Stop Words
STOP_WORDS: Set[str] = set()
try:
    rules_path = os.path.join(SRC_DIR, "language_rules.json")
    if os.path.exists(rules_path):
        with open(rules_path, "r", encoding="utf-8") as f:
            rules_data = json.load(f)
            STOP_WORDS = set(rules_data.get("IGNORED_TOKENS", {}).get("STOP_WORDS", []))
except Exception:
    STOP_WORDS = {
        'to', 'please', 'is', 'then', 'than', 'तो', 'का', 'की', 'को', 'hai', 'se',
        'అని', 'కు', 'కి', 'లో', 'నుంచి', 'তা', 'এটা', 'হয়', 'হে', 'ला', 'चे', 'छ', 'लाई', 'गर्नुहोस्'
    }


@dataclass
class Issue:
    id: str
    kind: str
    stage: str
    severity: str        # "critical", "high", "medium", "low", "info"
    line: int
    column: int
    evidence: str
    message: str
    fixable: bool
    fixer_hint: str      # e.g. "deterministic:homoglyph", "deterministic:dead_code", "ai:gemini"
    source: str          # "lexer"|"parser"|"semantic"|"dead_code"|"sast"|"ai"|"runtime"
    name: str = ""
    rule_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "stage": self.stage,
            "severity": self.severity.lower(),
            "line": self.line,
            "column": self.column,
            "evidence": self.evidence,
            "message": self.message,
            "fixable": self.fixable,
            "fixer_hint": self.fixer_hint,
            "source": self.source,
            "name": self.name,
            "rule_id": self.rule_id
        }


class StageCountDict(dict):
    """Dictionary for stage counts with transparent integer and string key lookup."""
    def __getitem__(self, key):
        k = str(key) if isinstance(key, int) else key
        return super().get(k, 0)

    def get(self, key, default=0):
        k = str(key) if isinstance(key, int) else key
        return super().get(k, default)


def counts_by_stage(issues: List[Issue]) -> Dict[Any, int]:
    """Returns mapping of stage_id (both string and int 1..14) -> count."""
    counts: Dict[str, int] = StageCountDict({s: 0 for s in ALL_STAGE_IDS})
    for idx in range(1, 15):
        counts[str(idx)] = 0
    for issue in issues:
        stg = issue.stage
        if stg in ALL_STAGE_IDS:
            counts[stg] += 1
            idx = str(ALL_STAGE_IDS.index(stg) + 1)
            counts[idx] += 1
        elif isinstance(stg, int) and 1 <= stg <= 14:
            counts[str(stg)] += 1
            counts[ALL_STAGE_IDS[stg - 1]] += 1
    return counts


def counts_by_severity(issues: List[Issue]) -> Dict[str, int]:
    """Returns mapping of severity -> count."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for issue in issues:
        sev = (issue.severity or "low").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def total_fixable(issues: List[Issue]) -> int:
    """Returns total count of fixable issues in the collection."""
    return sum(1 for issue in issues if issue.fixable)


def _classify_security_kind(rule_id: str, title: str) -> Tuple[str, str, str]:
    """Returns (kind, severity, fixer_hint) for a security finding."""
    r = rule_id.upper()
    t = title.lower()

    if "SEC-RUN-001" in r or "infinite loop" in t:
        return "infinite_loop", "high", "deterministic:runtime"
    if "SEC-INJ-001" in r or "sql" in t or "cwe-89" in t:
        return "sql_injection", "critical", "deterministic:security"
    if "SEC-IR-001" in r or "eval" in t or "cwe-95" in t:
        return "dynamic_eval", "critical", "deterministic:security"
    if "SEC-INJ-002" in r or "command injection" in t or "cwe-78" in t:
        return "command_injection", "critical", "deterministic:security"
    if "SEC-SEC-001" in r or "secret" in t or "cwe-798" in t:
        return "hardcoded_secret", "high", "deterministic:security"
    if "SEC-PAT-001" in r or "traversal" in t or "cwe-22" in t:
        return "path_traversal", "high", "deterministic:security"
    if "SEC-AUTH-" in r or "authorization" in t or "idor" in t or "cwe-639" in t:
        return "missing_authorization", "high", "deterministic:security"
    if "SEC-BUS-" in r or "business logic" in t or "workflow" in t or "discount" in t or "quantity" in t:
        return "business_logic", "high", "deterministic:security"

    sev = "high" if "critical" in t or "cwe-89" in t or "cwe-95" in t else ("medium" if "medium" in t else "low")
    return "security_finding", sev, "deterministic:security"


def collect_issues(
    source: str,
    language: str = "english",
    run_result: Optional[Any] = None
) -> List[Issue]:
    """
    Collects all diagnostics across lexical, syntax, semantic, dead code, SAST,
    runtime, and AI stages into ONE unified, deduplicated collection.
    
    Deduplicates strictly by (kind, line, column, message).
    """
    raw_issues: List[Issue] = []
    source_str = source or ""
    if not source_str.strip():
        return []

    lines = source_str.splitlines()
    detected_lang = VitalLanguageIntelligence.detect_language(source_str)
    effective_lang = language if language and language != "English" else detected_lang

    # -------------------------------------------------------------------------
    # 1. LEXICAL ANALYSIS (Stage 2, source="lexer")
    # -------------------------------------------------------------------------
    # Homoglyphs and lookalikes in code positions
    lex_findings = DeterministicSecurityScanner.scan_lexical(source_str, include_homoglyphs=True)
    for f in lex_findings:
        rule = getattr(f, "rule_id", "SEC-LEX-001")
        line_no = getattr(f, "line", 1) or 1
        col_no = getattr(f, "column", 1) or 1
        ev = getattr(f, "evidence", "") or (lines[line_no - 1] if 1 <= line_no <= len(lines) else "")
        msg = getattr(f, "message", "") or getattr(f, "title", "Lexical finding")

        if rule in ("SEC-LEX-002", "SEC-LEX-003"):
            raw_issues.append(Issue(
                id=f"ISSUE-LEX-homoglyph-L{line_no}C{col_no}",
                kind="homoglyph",
                stage="lexical_analysis",
                severity="low",
                line=line_no,
                column=col_no,
                evidence=ev,
                message=msg,
                fixable=True,
                fixer_hint="deterministic:homoglyph",
                source="lexer",
                name=msg,
                rule_id=rule
            ))
        elif "backtick" in msg.lower() or "`" in ev:
            raw_issues.append(Issue(
                id=f"ISSUE-LEX-backtick-L{line_no}C{col_no}",
                kind="invalid_character",
                stage="lexical_analysis",
                severity="medium",
                line=line_no,
                column=col_no,
                evidence=ev,
                message=msg,
                fixable=True,
                fixer_hint="deterministic:homoglyph",
                source="lexer",
                name=msg,
                rule_id="LEX-BACKTICK"
            ))
        elif "null byte" in msg.lower() or rule == "SEC-LEX-001":
            raw_issues.append(Issue(
                id=f"ISSUE-LEX-nullbyte-L{line_no}C{col_no}",
                kind="null_byte",
                stage="lexical_analysis",
                severity="critical",
                line=line_no,
                column=col_no,
                evidence=ev,
                message=msg,
                fixable=False,
                fixer_hint="",
                source="lexer",
                name=msg,
                rule_id=rule
            ))
        else:
            # Any other lexical diagnostic belongs to lexical_analysis
            raw_issues.append(Issue(
                id=f"ISSUE-LEX-{rule}-L{line_no}C{col_no}",
                kind="lexical_security",
                stage="lexical_analysis",
                severity=str(getattr(f, "severity", "critical")).lower(),
                line=line_no,
                column=col_no,
                evidence=ev,
                message=msg,
                fixable=True,
                fixer_hint="deterministic:lexical",
                source="lexer",
                name=msg,
                rule_id=rule
            ))

    # -------------------------------------------------------------------------
    # 2. SYNTAX & PARSER ANALYSIS (Stage 3, source="parser")
    # -------------------------------------------------------------------------
    parser_findings = DeterministicSecurityScanner.scan_parser(source_str)
    for pf in parser_findings:
        line_no = getattr(pf, "line", 1) or 1
        col_no = getattr(pf, "column", 1) or 1
        ev = getattr(pf, "evidence", "") or (lines[line_no - 1] if 1 <= line_no <= len(lines) else "")
        msg = getattr(pf, "title", "Syntax error")
        rule = getattr(pf, "rule_id", "SEC-PAR-001")

        if "delimiter" in msg.lower() or "bracket" in msg.lower() or "brace" in msg.lower() or rule == "SEC-PAR-001":
            raw_issues.append(Issue(
                id=f"ISSUE-SYN-delimiter-L{line_no}C{col_no}",
                kind="unbalanced_delimiter",
                stage="syntax_analysis",
                severity="critical",
                line=line_no,
                column=col_no,
                evidence=ev,
                message=msg,
                fixable=True,
                fixer_hint="deterministic:delimiter",
                source="parser",
                name=msg,
                rule_id=rule
            ))
        else:
            raw_issues.append(Issue(
                id=f"ISSUE-SYN-syntax-L{line_no}C{col_no}",
                kind="syntax_error",
                stage="syntax_analysis",
                severity="critical",
                line=line_no,
                column=col_no,
                evidence=ev,
                message=msg,
                fixable=True,
                fixer_hint="ai:gemini",
                source="parser",
                name=msg,
                rule_id=rule
            ))

    # -------------------------------------------------------------------------
    # 3. SEMANTIC ANALYSIS (Stage 5, source="semantic")
    # -------------------------------------------------------------------------
    # Check stop words used as identifiers
    from web.code_health import analyze_health
    health_data = analyze_health(source_str, language=effective_lang, skip_collector=True)
    for err in health_data.get("errors", []):
        stg_num = err.get("stage", 3)
        stg_id = "syntax_analysis" if stg_num == 3 else ("semantic_analysis" if stg_num == 5 else "lexical_analysis")
        lno = err.get("line", 1) or 1
        cno = err.get("column", 1) or 1
        msg = err.get("message", "Compiler error")
        ev = lines[lno - 1] if 1 <= lno <= len(lines) else ""
        code = err.get("code", "ERR")

        kind = "semantic_error"
        hint = "ai:gemini"
        if "division by zero" in msg.lower() or code == "SEM-002":
            kind = "division_by_zero"
            hint = "deterministic:runtime"
        elif "undefined" in msg.lower() or "referenced before" in msg.lower() or "undeclared" in msg.lower() or "did you mean" in msg.lower():
            kind = "undefined_variable"
            hint = "deterministic:undefined_variable"

        raw_issues.append(Issue(
            id=f"ISSUE-SEM-{kind}-L{lno}C{cno}",
            kind=kind,
            stage=stg_id,
            severity="critical" if stg_num == 3 else "high",
            line=lno,
            column=cno,
            evidence=ev,
            message=msg,
            fixable=True,
            fixer_hint=hint,
            source="semantic" if stg_num == 5 else "parser",
            name=msg,
            rule_id=code
        ))

    # Stop words in identifiers check
    for lno, line in enumerate(lines, start=1):
        clean_l = line.split("//")[0].split("#")[0]
        # Strip string literals so words in strings are not treated as identifiers
        clean_l = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"|\'[^\'\\]*(?:\\.[^\'\\]*)*\'', '', clean_l)
        # Match identifier tokens
        for word in re.findall(r'[\u0900-\u0D7F\w]+', clean_l):
            if word in STOP_WORDS:
                raw_issues.append(Issue(
                    id=f"ISSUE-SEM-stopword-{word}-L{lno}",
                    kind="stop_word",
                    stage="semantic_analysis",
                    severity="high",
                    line=lno,
                    column=clean_l.find(word) + 1,
                    evidence=line.strip(),
                    message=f"Stop word '{word}' from language rules used as identifier.",
                    fixable=True,
                    fixer_hint="deterministic:stop_word",
                    source="semantic",
                    name=word,
                    rule_id="SEM-STOP-WORD"
                ))

    # -------------------------------------------------------------------------
    # 4. DEAD CODE (Stage 5 / Semantic, source="dead_code")
    # -------------------------------------------------------------------------
    dead_items = health_data.get("dead_code", {}).get("items", [])
    for d in dead_items:
        lno = d.get("line", 1) or 1
        cno = d.get("column", 1) or 1
        k = d.get("kind", "dead_code")
        name = d.get("name", "")
        ev = d.get("evidence", "") or (lines[lno - 1] if 1 <= lno <= len(lines) else "")
        msg = d.get("message", f"Dead code: unused {k}")

        raw_issues.append(Issue(
            id=f"ISSUE-DEAD-{k}-{name}-L{lno}",
            kind=k,
            stage="semantic_analysis",
            severity="low",
            line=lno,
            column=cno,
            evidence=ev,
            message=msg,
            fixable=True,
            fixer_hint=f"deterministic:{k}",
            source="dead_code",
            name=name,
            rule_id=k
        ))

    # -------------------------------------------------------------------------
    # 5. SAST SECURITY FINDINGS (Stage 11, source="sast")
    # -------------------------------------------------------------------------
    sec_full = security_coordinator.run_full_scan(source_str, language=effective_lang, use_ai_enrichment=False)
    for sf in sec_full.get("findings", []):
        r_id = sf.get("rule_id", "SEC-001")
        # All lexical rules belong to lexer stage (Stage 2), skip duplicates in SAST
        if r_id.startswith("SEC-LEX-") or r_id.startswith("LEX-"):
            continue
        lno = sf.get("line", 1) or 1
        cno = sf.get("column", 1) or 1
        ev = sf.get("evidence", "") or (lines[lno - 1] if 1 <= lno <= len(lines) else "")
        title = sf.get("title", sf.get("message", "Security vulnerability"))
        kind, sev, hint = _classify_security_kind(r_id, title)

        raw_issues.append(Issue(
            id=f"ISSUE-SEC-{r_id}-L{lno}",
            kind=kind,
            stage="security_analysis",
            severity=sev,
            line=lno,
            column=cno,
            evidence=ev,
            message=title,
            fixable=True,
            fixer_hint=hint,
            source="sast",
            name=title,
            rule_id=r_id
        ))

    # -------------------------------------------------------------------------
    # 6. RUNTIME / EXECUTION BOUNDARY (Stage 13, source="runtime")
    # -------------------------------------------------------------------------
    exec_findings = DeterministicSecurityScanner.scan_execution_boundary(source_str)
    for ef in exec_findings:
        r_id = getattr(ef, "rule_id", "SEC-RUN-001")
        lno = getattr(ef, "line", 1) or 1
        cno = getattr(ef, "column", 1) or 1
        ev = getattr(ef, "evidence", "") or (lines[lno - 1] if 1 <= lno <= len(lines) else "")
        title = getattr(ef, "title", "Runtime boundary violation")

        raw_issues.append(Issue(
            id=f"ISSUE-RUN-{r_id}-L{lno}",
            kind="infinite_loop" if r_id == "SEC-RUN-001" else "runtime_error",
            stage="sandbox_execution",
            severity="high",
            line=lno,
            column=cno,
            evidence=ev,
            message=title,
            fixable=True,
            fixer_hint="deterministic:runtime",
            source="runtime",
            name=title,
            rule_id=r_id
        ))

    # -------------------------------------------------------------------------
    # 7. RUN RESULT ENRICHMENT (if pipeline tracker run result provided)
    # -------------------------------------------------------------------------
    if run_result:
        stages_data = {}
        if hasattr(run_result, "stages"):
            stages_data = run_result.stages
        elif isinstance(run_result, dict):
            stages_data = run_result.get("stages", {})
            if isinstance(stages_data, list):
                stages_data = {s.get("id"): s for s in stages_data if isinstance(s, dict)}

        # Stage 12 AI findings if present
        st12 = stages_data.get("ai_security_analysis", {})
        if st12 and st12.get("status") in ("warning", "failed"):
            for af in st12.get("details", {}).get("findings", []):
                lno = af.get("line", 1) or 1
                cno = af.get("column", 1) or 1
                ev = af.get("evidence", "")
                cur_line_text = lines[lno - 1] if 1 <= lno <= len(lines) else ""
                if ev and ev.strip() and ev.strip() not in cur_line_text and ev.strip() not in source_str:
                    continue
                ev_to_use = ev or cur_line_text
                msg = af.get("message", "AI security finding")
                raw_issues.append(Issue(
                    id=f"ISSUE-AI-L{lno}C{cno}",
                    kind="ai_finding",
                    stage="ai_security_analysis",
                    severity="high",
                    line=lno,
                    column=cno,
                    evidence=ev_to_use,
                    message=msg,
                    fixable=True,
                    fixer_hint="ai:gemini",
                    source="ai"
                ))

    # -------------------------------------------------------------------------
    # 8. DEDUPLICATION STRICTLY BY (kind, line, column, message)
    # -------------------------------------------------------------------------
    deduped_issues: List[Issue] = []
    seen: Set[Tuple[str, int, int, str]] = set()

    for item in raw_issues:
        key = (item.kind, item.line, item.column, item.message.strip().lower())
        if key not in seen:
            seen.add(key)
            deduped_issues.append(item)

    # Sort deterministically by (line, column, stage, id)
    deduped_issues.sort(key=lambda i: (i.line, i.column, i.stage, i.id))
    return deduped_issues
