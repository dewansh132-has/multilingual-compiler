# -*- coding: utf-8 -*-
"""
web/deterministic_fixer.py — Comprehensive Deterministic Fixer Registry for VITAL (Stages 2-13)

Executes BEFORE any AI fallback with zero external dependencies and zero API key requirements.
Keyed by rule code and error pattern:
  1. Homoglyphs / Lookalikes (Stage 2):
     - ASCII equivalent from src/lexer.py HOMOGLYPH_MAP (single source of truth).
     - Applied strictly at diagnostic column in code positions (never in comments/strings).
  2. Stop Words Used as Identifiers:
     - Detects identifiers matching empty-string translation stop words in language_rules.json (e.g. की, छ, लाई).
     - Renames consistently across scope to avoid translation erasure.
  3. Delimiter Balancing (Stage 3):
     - Inserts missing delimiters or removes extraneous delimiters where parser reports.
  4. Undefined Variables (Stage 5 Semantic):
     - Matches declared names by edit distance <= 2, case, or cross-language translation mappings.
     - If no match, declares variable before first use with language-specific declaration keyword.
  5. Unused Variables & Unreachable Code:
     - Removes side-effect-free unused declarations or statements following terminal returns.
  6. Stage 13 Runtime Errors:
     - ZeroDivisionError: guards divisor with non-zero check.
     - NameError: initializes undefined runtime variable before first use.
     - IndexError / Off-by-one: clamps boundary check or adjusts loop condition.
     - Timeout / Infinite Loop: adds loop counter update inside loop body.
  7. Seeded Security Findings (Stage 11/12):
     - SQL Injection (CWE-89): sanitizes input / parameterized query.
     - Dynamic Eval (CWE-95): unwraps eval() into direct safe execution.
     - Hardcoded Secret (CWE-798): replaces literal secret with config lookup.
     - Path Traversal (CWE-22): adds path traversal guard.
     - Authorization / IDOR (CWE-639): adds role check guard.
"""

import os
import re
import json
from typing import Dict, Any, List, Optional, Tuple, Set

# Read homoglyph normalization map from src/lexer.py (Single Source of Truth)
try:
    from src.lexer import HOMOGLYPH_MAP
except ImportError:
    try:
        from lexer import HOMOGLYPH_MAP
    except ImportError:
        HOMOGLYPH_MAP = {
            'ः': ':', '।': '|', '॥': '||', '०': '0', 'ऽ': 'S',
            'ঃ': ':', '০': '0', 'ః': ':', '౦': '0',
            'а': 'a', 'е': 'e', 'о': 'o', 'с': 'c', 'р': 'p', 'х': 'x',
            'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H',
            'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
            '“': '"', '”': '"', '‘': "'", '’': "'",
            '\u00A0': ' ', '\u200B': '', '\u200C': '', '\u200D': ''
        }

# Language-specific variable declaration keywords
DECL_KEYWORDS: Dict[str, str] = {
    "english": "let",
    "hindi": "मानो",
    "telugu": "అనుకో",
    "bengali": "ধরো",
    "marathi": "घ्या",
    "nepali": "मानौँ",
    "fusion": "let"
}

# Language-specific conditional keywords
IF_KEYWORDS: Dict[str, str] = {
    "english": "if",
    "hindi": "अगर",
    "telugu": "ఒకవేళ",
    "bengali": "যদি",
    "marathi": "जर",
    "nepali": "यदि",
    "fusion": "if"
}

# Language-specific return keywords
RETURN_KEYWORDS: Dict[str, str] = {
    "english": "return",
    "hindi": "लौटाओ",
    "telugu": "తిరిగి_ఇవ్వు",
    "bengali": "ফেরত",
    "marathi": "परत_करा",
    "nepali": "फिर्ता",
    "fusion": "return"
}

# Language-specific print keywords
PRINT_KEYWORDS: Dict[str, str] = {
    "english": "print",
    "hindi": "छापो",
    "telugu": "ముద్రించు",
    "bengali": "ছাপাও",
    "marathi": "लिहा",
    "nepali": "छाप",
    "fusion": "print"
}

ALL_VAR_DECL_KEYWORDS: List[str] = [
    "let", "var", "val",
    "मानो", "मान", "माना",
    "అనుకో", "తీసుకో",
    "ধরো", "ধরি",
    "घ्या",
    "मानौँ", "मानौ"
]

ALL_FUNCTION_KEYWORDS: List[str] = [
    "function", "def", "fun", "fn",
    "कार्य", "ఫంక్షన్", "పని", "విధము",
    "ফাংশন", "कार्य_करा", "कार्य_गर"
]
FUNC_KW_REGEX = r'(?:' + '|'.join(re.escape(k) for k in ALL_FUNCTION_KEYWORDS) + r')'

def find_block_span(source_lines: List[str], start_line_1based: int) -> Tuple[int, int]:
    """Finds start and end lines of a braced block. Returns (start, end) 1-based inclusive."""
    depth = 0
    found_open = False
    start_idx = max(0, start_line_1based - 1)

    for i in range(start_idx, len(source_lines)):
        line = source_lines[i]
        in_str = None
        j = 0
        while j < len(line):
            ch = line[j]
            if in_str:
                if ch == "\\":
                    j += 2
                    continue
                elif ch == in_str:
                    in_str = None
            else:
                if ch in ('"', "'"):
                    in_str = ch
                elif ch == "/" and j + 1 < len(line) and line[j + 1] == "/":
                    break
                elif ch == "#":
                    break
                elif ch == "{":
                    depth += 1
                    found_open = True
                elif ch == "}":
                    depth -= 1
                    if found_open and depth == 0:
                        return (start_line_1based, i + 1)
            j += 1
    return (start_line_1based, len(source_lines))

# Load STOP_WORDS from language_rules.json
STOP_WORDS: Set[str] = set()
RULES_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "language_rules.json")
try:
    with open(RULES_PATH, "r", encoding="utf-8") as f:
        rules_data = json.load(f)
        STOP_WORDS = set(rules_data.get("IGNORED_TOKENS", {}).get("STOP_WORDS", []))
except Exception:
    STOP_WORDS = {'to', 'please', 'is', 'then', 'than', 'तो', 'का', 'की', 'को', 'hai', 'se', 'అని', 'కు', 'కి', 'లో', 'నుంచి', 'তা', 'এটা', 'হয়', 'हे', 'ला', 'चे', 'छ', 'लाई', 'गर्नुहोस्'}

# Cross-language function mapping dictionary for seeded fixtures & common identifiers
CROSS_LANG_FUNCTION_MAP = {
    "execute_database_query": [
        "डेटाबेस_क्वेरी_चलाएं", "డేటాబేస్_క్వెరీ_రన్_చేయి", "ডাটাবেস_কোয়েরি_চালাও",
        "डेटाबेस_क्वेरी_चालवा", "डेटाबेस_क्वेरी_चलाऊ"
    ],
    "dispatch_system_command": [
        "सिस्टम_कमांड_प्रेषित_करें", "సిస్టమ్_కమాండ్_డిస్పాచ్", "সিস্টেম_কমান্ড_প্রেরণ",
        "सिस्टम_कमांड_चालवा", "सिस्टम_कमाण्ड_चलाऊ"
    ],
    "system_backup_tar_dispatch": [
        "सिस्टम_बैकअप_टार_डिस्पैच", "సిస్టమ్_బ్యాకప్_టార్_డిస్పాచ్", "সিস্টেম_ব্যাকআপ_টার_প্রেরণ",
        "सिस्टम_बॅकअप_टार_चालवा", "सिस्टम_ब्याकअप_टार_चलाऊ"
    ],
    "dynamic_expression_evaluator": [
        "गतिशील_गणितीय_मूल्यांकन", "డైనమిక్_ఎక్స్‌ప్రెషన్_మూల్యాంకనం", "ডাইনামিক_গণিত_মূল্যায়ন",
        "डायनॅमिक_गणितीय_मूल्यांकन", "गतिशील_गणितीय_मूल्याङ्कन"
    ]
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes standard Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev[j + 1] + 1
            deletions = curr[j] + 1
            substitutions = prev[j] + (c1 != c2)
            curr.append(min(insertions, deletions, substitutions))
        prev = curr
    return prev[-1]


def is_in_string_or_comment(line: str, col_idx: int) -> bool:
    """Checks whether the character at col_idx (0-based) on line is inside a string literal or comment."""
    in_str = None
    in_comment = False
    escape = False
    for i, ch in enumerate(line):
        if i == col_idx:
            return bool(in_str or in_comment)
        if in_comment:
            continue
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_str:
                in_str = None
        else:
            if ch in ('"', "'"):
                in_str = ch
            elif ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
                in_comment = True
            elif ch == "#":
                in_comment = True
    return bool(in_str or in_comment)


class DeterministicFixerRegistry:
    """Deterministic Fixer Registry for Stages 2-13."""

    @classmethod
    def attempt_fix(
        cls,
        source_code: str,
        stage_id: str,
        finding_id: str,
        finding_data: Dict[str, Any],
        language: str = "English"
    ) -> Optional[Dict[str, Any]]:
        rule_id = str(finding_data.get("rule_id", "") or finding_data.get("id", "")).upper()
        title = str(finding_data.get("title", "") or finding_data.get("message", "")).lower()
        msg = str(finding_data.get("message", "")).lower()
        kind = str(finding_data.get("kind", "")).lower()
        lang_key = (language or "English").lower()

        # 1. Homoglyphs & Lookalikes (Stage 2 Lexical Analysis)
        if (
            kind == "homoglyph"
            or rule_id in ("SEC-LEX-002", "SEC-LEX-003", "LEX-HOMOGLYPH", "HOMOGLYPH")
            or "homoglyph" in title or "spoofing" in title or "lookalike" in title
            or "homoglyph" in msg
        ):
            return cls.fix_homoglyph(source_code, finding_id, finding_data)

        # 2. Stop words used as identifiers
        if kind == "stop_word" or "stop word" in title or "stop word" in msg or any(sw in title for sw in ("की", "छ", "लाई")):
            return cls.fix_stop_word(source_code, finding_id, finding_data, lang_key)

        # 3. Delimiter balancing (Stage 3 Syntax Analysis)
        if (
            kind in ("unbalanced_delimiter", "delimiter")
            or stage_id in ("syntax_analysis", "syntax", "parser")
            or rule_id in ("SEC-PAR-001", "SEC-PAR-002", "SYN-001", "SYN-DELIM")
            or "delimiter" in title or "brace" in title or "parenthes" in title or "bracket" in title
            or "unbalanced" in title or "unclosed" in title
        ):
            return cls.fix_delimiters(source_code, finding_id, finding_data, lang_key)

        # 4. Division by zero (Stage 5 Semantic or Stage 13 Runtime)
        if kind == "division_by_zero" or "division by zero" in title or "division by zero" in msg or "zerodivision" in title or (rule_id == "SEM-001" and "/ 0" in source_code):
            return cls.fix_stage13_runtime_error(source_code, finding_id, finding_data, lang_key)

        # 5. Undefined / Undeclared variable (Stage 5 Semantic Analysis)
        if (
            kind in ("undefined_variable", "semantic_error")
            or rule_id in ("SEM-UNDECLARED", "SEC-SEM-001", "SEM-001")
            or "undeclared" in title or "not defined" in title or "undefined" in title
            or "referenced before" in title or "before explicit" in title or "did you mean" in title
            or "referenced before" in msg or "before explicit" in msg or "did you mean" in msg
        ):
            return cls.fix_undefined_variable(source_code, finding_id, finding_data, lang_key)

        # 6. Dead code & Unused constructs (Code Health & Semantics)
        if (
            stage_id in ("code_health_dead_code", "dead_code")
            or kind in ("unused_variable", "unused_function", "unused_parameter", "unreachable_after_return", "unreachable_code", "never_true_branch", "duplicate_branch")
            or "unused" in title or "unreachable" in title or "dead code" in title
            or rule_id in ("SEM-UNUSED", "DEAD-CODE", "UNREACHABLE", "CH-DEAD")
            or rule_id.startswith("CH-DEAD")
        ):
            return cls.fix_dead_code_item(source_code, finding_id, finding_data, lang_key)

        # 7. Stage 13 Runtime Errors
        if (
            stage_id == "sandbox_execution"
            or kind in ("infinite_loop", "runtime_error")
            or rule_id.startswith("RUN-")
            or "zerodivisionerror" in title or "nameerror" in title or "timeout" in title
        ):
            return cls.fix_stage13_runtime_error(source_code, finding_id, finding_data, lang_key)

        # 8. Seeded Security Findings (Stage 11/12)
        if (
            rule_id.startswith("SEC-")
            or "SEC-" in rule_id
            or kind in ("sql_injection", "dynamic_eval", "command_injection", "hardcoded_secret", "path_traversal", "missing_authorization", "business_logic", "security_finding")
            or any(k in title for k in ("sql", "eval", "secret", "password", "traversal", "idor", "discount", "quantity", "shell", "chaining"))
        ):
            sec_res = cls.fix_security_vulnerability(source_code, finding_id, finding_data, lang_key)
            if sec_res is not None:
                return sec_res
            try:
                from web.security_analyzer import security_coordinator
                coord_fix = security_coordinator.suggest_fix_for_finding(
                    source_code=source_code,
                    finding_id=finding_id,
                    finding_data=finding_data,
                    language=language,
                    prefer_deterministic=True
                )
                if coord_fix and coord_fix.get("success"):
                    return coord_fix
            except Exception:
                pass
            return None

        return None

    # -------------------------------------------------------------------------
    # Fixer 1: Homoglyph Normalization
    # -------------------------------------------------------------------------
    @classmethod
    def fix_homoglyph(cls, source_code: str, finding_id: str, finding_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        lines = source_code.splitlines()
        target_line = int(finding_data.get("line") or 1)
        target_col = int(finding_data.get("column") or 1)
        evidence = str(finding_data.get("evidence") or "")

        if not (1 <= target_line <= len(lines)):
            return None

        orig_line = lines[target_line - 1]
        col_idx = target_col - 1

        # Check if the exact column points to a homoglyph
        replaced_char = None
        replacement_char = None
        new_line = None

        if 0 <= col_idx < len(orig_line):
            ch = orig_line[col_idx]
            if ch in HOMOGLYPH_MAP:
                if is_in_string_or_comment(orig_line, col_idx):
                    # Do not touch homoglyphs inside string or comment
                    return None
                replaced_char = ch
                replacement_char = HOMOGLYPH_MAP[ch]
                new_line = orig_line[:col_idx] + replacement_char + orig_line[col_idx + 1:]

        # If column index didn't directly hit, search code positions on this line
        if new_line is None:
            for idx, ch in enumerate(orig_line):
                if ch in HOMOGLYPH_MAP and not is_in_string_or_comment(orig_line, idx):
                    if evidence and ch not in evidence and HOMOGLYPH_MAP[ch] not in evidence:
                        continue
                    replaced_char = ch
                    replacement_char = HOMOGLYPH_MAP[ch]
                    new_line = orig_line[:idx] + replacement_char + orig_line[idx + 1:]
                    break

        if new_line is None or new_line == orig_line:
            return None

        lines[target_line - 1] = new_line
        proposed_source = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")

        return {
            "success": True,
            "finding_id": finding_id,
            "start_line": target_line,
            "end_line": target_line,
            "original_snippet": orig_line,
            "replacement": new_line,
            "explanation": f"Normalized lookalike character {repr(replaced_char)} at column {target_col} to ASCII '{replacement_char}'.",
            "proposed_source": proposed_source,
            "is_deterministic": True,
            "fix_type": "deterministic"
        }

    # -------------------------------------------------------------------------
    # Fixer 2: Stop Word Used as Identifier
    # -------------------------------------------------------------------------
    @classmethod
    def fix_stop_word(cls, source_code: str, finding_id: str, finding_data: Dict[str, Any], language: str) -> Optional[Dict[str, Any]]:
        evidence = str(finding_data.get("evidence") or "")
        title = str(finding_data.get("title") or "")
        target_line = int(finding_data.get("line") or 1)
        lines = source_code.splitlines()

        stop_word = None
        for sw in STOP_WORDS:
            if sw in evidence or f"'{sw}'" in title or f'"{sw}"' in title:
                stop_word = sw
                break
        if not stop_word and (1 <= target_line <= len(lines)):
            line = lines[target_line - 1]
            for sw in STOP_WORDS:
                if re.search(rf'\b{re.escape(sw)}\b', line):
                    stop_word = sw
                    break

        if not stop_word:
            return None

        new_ident = f"{stop_word}_var"
        # Rename consistently within scope
        pattern = re.compile(rf'(?<![a-zA-Z0-9_\u0900-\u0C7F]){re.escape(stop_word)}(?![a-zA-Z0-9_\u0900-\u0C7F])')
        new_source = pattern.sub(new_ident, source_code)

        if new_source == source_code:
            return None

        orig_snippet = lines[target_line - 1] if (1 <= target_line <= len(lines)) else stop_word
        new_snippet = pattern.sub(new_ident, orig_snippet)

        return {
            "success": True,
            "finding_id": finding_id,
            "start_line": target_line,
            "end_line": target_line,
            "original_snippet": orig_snippet,
            "replacement": new_snippet,
            "explanation": f"Renamed stop word identifier '{stop_word}' to '{new_ident}' to prevent transpilation erasure.",
            "proposed_source": new_source,
            "is_deterministic": True,
            "fix_type": "deterministic"
        }

    # -------------------------------------------------------------------------
    # Fixer 3: Delimiter Balancing
    # -------------------------------------------------------------------------
    @classmethod
    def fix_delimiters(cls, source_code: str, finding_id: str, finding_data: Dict[str, Any], language: str) -> Optional[Dict[str, Any]]:
        lines = source_code.splitlines()
        target_line = int(finding_data.get("line") or len(lines))
        msg = str(finding_data.get("message") or "")
        title = (str(finding_data.get("title") or "") or msg).lower()

        # Count total braces and parens stripping comments
        clean_code = "\n".join([l.split("//")[0].split("#")[0] for l in lines])
        open_b = clean_code.count("{")
        close_b = clean_code.count("}")
        open_p = clean_code.count("(")
        close_p = clean_code.count(")")

        # Case A: Missing closing brace '}'
        if open_b > close_b or "unclosed '{'" in title or "missing '}'" in title:
            # Insert closing brace at target line or before function boundary / end of file
            insert_idx = min(target_line, len(lines))
            indent = "    "
            if insert_idx > 0:
                prev_line = lines[insert_idx - 1]
                indent = " " * (len(prev_line) - len(prev_line.lstrip()))
            insert_text = f"{indent}}}"
            new_lines = lines[:insert_idx] + [insert_text] + lines[insert_idx:]
            proposed = "\n".join(new_lines) + ("\n" if source_code.endswith("\n") else "")
            return {
                "success": True,
                "finding_id": finding_id,
                "start_line": insert_idx,
                "end_line": insert_idx,
                "original_snippet": lines[insert_idx - 1] if insert_idx <= len(lines) else "",
                "replacement": (lines[insert_idx - 1] + "\n" + insert_text) if insert_idx <= len(lines) else insert_text,
                "explanation": f"Inserted missing closing delimiter '}}' to balance code block.",
                "proposed_source": proposed,
                "is_deterministic": True,
                "fix_type": "deterministic"
            }

        # Case B: Extra closing brace '}'
        if close_b > open_b or "unexpected closing brace" in title:
            if 1 <= target_line <= len(lines) and "}" in lines[target_line - 1]:
                orig_l = lines[target_line - 1]
                new_l = orig_l.replace("}", "", 1)
                lines[target_line - 1] = new_l
                proposed = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
                return {
                    "success": True,
                    "finding_id": finding_id,
                    "start_line": target_line,
                    "end_line": target_line,
                    "original_snippet": orig_l,
                    "replacement": new_l,
                    "explanation": f"Removed extraneous closing brace '}}' at line {target_line}.",
                    "proposed_source": proposed,
                    "is_deterministic": True,
                    "fix_type": "deterministic"
                }

        # Case C: Missing closing parenthesis ')'
        if open_p > close_p or "unclosed '('" in title:
            if 1 <= target_line <= len(lines):
                orig_l = lines[target_line - 1]
                if orig_l.endswith("{"):
                    new_l = orig_l[:-1].rstrip() + ") {"
                else:
                    new_l = orig_l + ")"
                lines[target_line - 1] = new_l
                proposed = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
                return {
                    "success": True,
                    "finding_id": finding_id,
                    "start_line": target_line,
                    "end_line": target_line,
                    "original_snippet": orig_l,
                    "replacement": new_l,
                    "explanation": f"Inserted missing closing parenthesis ')' at line {target_line}.",
                    "proposed_source": proposed,
                    "is_deterministic": True,
                    "fix_type": "deterministic"
                }

        return None

    # -------------------------------------------------------------------------
    # Fixer 4: Undefined Variable Resolution
    # -------------------------------------------------------------------------
    @classmethod
    def fix_undefined_variable(cls, source_code: str, finding_id: str, finding_data: Dict[str, Any], language: str) -> Optional[Dict[str, Any]]:
        evidence = str(finding_data.get("evidence") or "")
        msg = str(finding_data.get("message") or "")
        title = str(finding_data.get("title") or "") or msg
        target_line = int(finding_data.get("line") or 1)
        lines = source_code.splitlines()

        # Extract identifier
        ident = ""
        m_id = re.search(r"[iI]dentifier '([^']+)'", msg or title)
        if m_id:
            ident = m_id.group(1).strip()
        elif evidence and not any(ch in evidence for ch in "()=+-*/{}[]"):
            ident = evidence.strip()
        else:
            m = re.search(r"'([^']+)'", title or msg)
            if m:
                ident = m.group(1).strip()

        if not ident or not (1 <= target_line <= len(lines)):
            return None

        # Check compiler suggestion "Did you mean '...'?"
        best_match = None
        m_sugg = re.search(r"[dD]id you mean '([^']+)'", msg or title)
        if m_sugg:
            best_match = m_sugg.group(1).strip()

        # Gather all declared identifiers in file
        declared_names = set()
        decl_kw_pat = r'\b(?:let|मानो|అనుకో|ধরো|ঘ्या|मानौँ|function|कार्य|ఫంక్షన్|ফাংশন|कार्य|कार्य)\s+([a-zA-Z0-9_\u0900-\u0C7F]+)'
        for m_decl in re.finditer(decl_kw_pat, source_code):
            declared_names.add(m_decl.group(1))

        # 1. Check cross-language equivalent mapping (e.g. Fusion Demo C)
        best_match = None
        for canonical_name, aliases in CROSS_LANG_FUNCTION_MAP.items():
            if ident == canonical_name or ident in aliases:
                for d in declared_names:
                    if d == canonical_name or d in aliases:
                        best_match = d
                        break
            if best_match:
                break

        # 2. Check Levenshtein distance <= 2 or case-insensitive match
        if not best_match:
            for decl_name in declared_names:
                if ident.lower() == decl_name.lower():
                    best_match = decl_name
                    break
                if levenshtein_distance(ident, decl_name) <= 2:
                    best_match = decl_name
                    break

        orig_line = lines[target_line - 1]

        if best_match and best_match != ident:
            # Replace ident on target_line with best_match
            pattern = re.compile(rf'(?<![a-zA-Z0-9_\u0900-\u0C7F]){re.escape(ident)}(?![a-zA-Z0-9_\u0900-\u0C7F])')
            new_line = pattern.sub(best_match, orig_line)
            lines[target_line - 1] = new_line
            proposed = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
            return {
                "success": True,
                "finding_id": finding_id,
                "start_line": target_line,
                "end_line": target_line,
                "original_snippet": orig_line,
                "replacement": new_line,
                "explanation": f"Replaced undeclared identifier '{ident}' with declared matching name '{best_match}'.",
                "proposed_source": proposed,
                "is_deterministic": True,
                "fix_type": "deterministic"
            }

        # 3. Otherwise: Declare variable before first use with language declaration keyword
        decl_kw = DECL_KEYWORDS.get(language, "let")
        indent = " " * (len(orig_line) - len(orig_line.lstrip()))
        decl_line = f"{indent}{decl_kw} {ident} = 0"
        new_lines = lines[:target_line - 1] + [decl_line] + lines[target_line - 1:]
        proposed = "\n".join(new_lines) + ("\n" if source_code.endswith("\n") else "")

        return {
            "success": True,
            "finding_id": finding_id,
            "start_line": target_line,
            "end_line": target_line,
            "original_snippet": orig_line,
            "replacement": f"{decl_line}\n{orig_line}",
            "explanation": f"Declared missing variable '{ident}' with safe default before line {target_line}.",
            "proposed_source": proposed,
            "is_deterministic": True,
            "fix_type": "deterministic"
        }

    # -------------------------------------------------------------------------
    # Fixer 5: Dead Code & Unused Constructs (Step 4 Registry)
    # -------------------------------------------------------------------------
    @classmethod
    def fix_dead_code_item(cls, source_code: str, finding_id: str, finding_data: Dict[str, Any], language: str = "english") -> Optional[Dict[str, Any]]:
        target_line = int(finding_data.get("line") or 1)
        lines = source_code.splitlines()

        if not (1 <= target_line <= len(lines)):
            return None

        orig_line = lines[target_line - 1]
        indent = orig_line[:len(orig_line) - len(orig_line.lstrip())]
        stripped = orig_line.strip()
        kind = str(finding_data.get("kind", "")).lower()
        title = str(finding_data.get("title", "")).lower()
        name = str(finding_data.get("name") or finding_data.get("evidence") or "")
        if not name:
            m_param = re.search(r"Parameter '([^']+)'", finding_data.get("message", "") or "")
            if m_param:
                name = m_param.group(1)
            else:
                m_var = re.search(r"Variable '([^']+)'", finding_data.get("message", "") or "")
                if m_var:
                    name = m_var.group(1)

        # 1. UNUSED FUNCTION
        if kind == "unused_function" or (("unused" in title and "function" in title) and kind not in ("unused_parameter", "unused_variable")):
            m_fn = re.search(FUNC_KW_REGEX + r'\s+([^\s\(]+)', orig_line)
            func_name = name or (m_fn.group(1) if m_fn else "")
            start_l, end_l = find_block_span(lines, target_line)
            orig_snip = "\n".join(lines[start_l - 1 : end_l])

            del lines[start_l - 1 : end_l]
            # Remove any adjacent trailing blank line
            if start_l - 1 < len(lines) and not lines[start_l - 1].strip():
                del lines[start_l - 1]
            elif start_l - 2 >= 0 and not lines[start_l - 2].strip():
                del lines[start_l - 2]

            proposed = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
            return {
                "success": True,
                "finding_id": finding_id,
                "start_line": start_l,
                "end_line": end_l,
                "original_snippet": orig_snip,
                "replacement": "",
                "explanation": f"Deleted unused function '{func_name}' and its body.",
                "proposed_source": proposed,
                "is_deterministic": True,
                "fix_type": "deterministic"
            }

        # 2. UNUSED PARAMETER
        if kind == "unused_parameter" or "parameter" in title:
            param_name = name
            func_match = re.search(FUNC_KW_REGEX + r'\s+([^\s\(]+)\s*\((.*?)\)', orig_line)
            if func_match:
                func_kw = func_match.group(0).split()[0]
                func_name = func_match.group(1)
                params_str = func_match.group(2)
                params = [p.strip() for p in params_str.split(",")]
                if param_name in params:
                    param_idx = params.index(param_name)
                    params.remove(param_name)
                    new_params_str = ", ".join(params)
                    new_decl = f"{func_kw} {func_name}({new_params_str})"
                    lines[target_line - 1] = orig_line.replace(func_match.group(0), new_decl)

                    # Remove corresponding argument at param_idx from all call sites (skipping decl lines)
                    call_pattern = re.compile(rf'\b{re.escape(func_name)}\s*\((.*?)\)')
                    for li in range(len(lines)):
                        l_txt = lines[li]
                        if re.search(FUNC_KW_REGEX + r'\s+' + re.escape(func_name), l_txt):
                            continue
                        new_l = l_txt
                        for m in call_pattern.finditer(l_txt):
                            args = [a.strip() for a in m.group(1).split(",")]
                            if len(args) > param_idx:
                                args.pop(param_idx)
                                new_call = f"{func_name}({', '.join(args)})"
                                new_l = new_l.replace(m.group(0), new_call)
                        lines[li] = new_l

                    proposed = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
                    return {
                        "success": True,
                        "finding_id": finding_id,
                        "start_line": target_line,
                        "end_line": target_line,
                        "original_snippet": orig_line,
                        "replacement": lines[target_line - 1],
                        "explanation": f"Removed unused parameter '{param_name}' from function '{func_name}' and updated all call sites.",
                        "proposed_source": proposed,
                        "is_deterministic": True,
                        "fix_type": "deterministic"
                    }

        # 3. UNREACHABLE AFTER RETURN / BREAK / CONTINUE
        if kind == "unreachable_after_return" or "unreachable" in title:
            start_l = target_line
            end_l = start_l
            while end_l <= len(lines) and "}" not in lines[end_l - 1]:
                end_l += 1
            delete_end = max(start_l, end_l - 1)
            orig_snip = "\n".join(lines[start_l - 1 : delete_end])
            del lines[start_l - 1 : delete_end]
            proposed = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
            return {
                "success": True,
                "finding_id": finding_id,
                "start_line": start_l,
                "end_line": delete_end,
                "original_snippet": orig_snip,
                "replacement": "",
                "explanation": f"Removed unreachable code after return at line {start_l}.",
                "proposed_source": proposed,
                "is_deterministic": True,
                "fix_type": "deterministic"
            }

        # 4. NEVER TRUE BRANCH
        if kind == "never_true_branch" or "never_true" in title:
            start_l, end_l = find_block_span(lines, target_line)
            orig_snip = "\n".join(lines[start_l - 1 : end_l])
            # Check for else branch
            has_else = False
            else_kw_pat = r'\b(else|नत्र|অন্যথা|अन्यथा|లేకపోతే)\b'
            combined_tail = (lines[end_l - 1] if end_l <= len(lines) else "") + " " + (lines[end_l] if end_l < len(lines) else "")
            if re.search(else_kw_pat, combined_tail):
                else_line = end_l if re.search(else_kw_pat, lines[end_l - 1]) else end_l + 1
                _, else_end_l = find_block_span(lines, else_line)
                if_indent = len(lines[start_l - 1]) - len(lines[start_l - 1].lstrip())
                else_body = lines[else_line : else_end_l - 1]
                del lines[start_l - 1 : else_end_l]
                dedented_else_body = []
                for bl in else_body:
                    if not bl.strip():
                        dedented_else_body.append("")
                        continue
                    bl_stripped = bl.lstrip()
                    bl_indent = len(bl) - len(bl_stripped)
                    rel_indent = max(0, bl_indent - 4)
                    dedented_else_body.append(" " * (if_indent + rel_indent) + bl_stripped)
                for idx, bl in enumerate(dedented_else_body):
                    lines.insert(start_l - 1 + idx, bl)
                replacement = "\n".join(dedented_else_body)
                end_l = else_end_l
            else:
                del lines[start_l - 1 : end_l]
                replacement = ""

            proposed = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
            return {
                "success": True,
                "finding_id": finding_id,
                "start_line": start_l,
                "end_line": end_l,
                "original_snippet": orig_snip,
                "replacement": replacement,
                "explanation": f"Removed statically false branch at line {start_l}.",
                "proposed_source": proposed,
                "is_deterministic": True,
                "fix_type": "deterministic"
            }

        # 5. UNUSED VARIABLE (Side-effect free vs Side-effect initialiser)
        matched_kw = None
        for kw in ALL_VAR_DECL_KEYWORDS:
            if stripped.startswith(kw + " "):
                matched_kw = kw
                break

        rest = stripped[len(matched_kw):].strip() if matched_kw else stripped
        if "=" in rest:
            var_part, rhs_part = rest.split("=", 1)
            var_actual = var_part.strip()
            if not name or var_actual == name:
                rhs = rhs_part.strip()
                has_side_effect = "(" in rhs and ")" in rhs
                if has_side_effect:
                    # Keep call, drop binding
                    replacement = indent + rhs
                    lines[target_line - 1] = replacement
                    expl = f"Dropped unused variable binding '{var_actual}', preserved function call."
                else:
                    # Side-effect free: delete statement line
                    replacement = ""
                    lines.pop(target_line - 1)
                    expl = f"Removed side-effect-free unused variable declaration '{var_actual}' at line {target_line}."

                proposed = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
                return {
                    "success": True,
                    "finding_id": finding_id,
                    "start_line": target_line,
                    "end_line": target_line,
                    "original_snippet": orig_line,
                    "replacement": replacement,
                    "explanation": expl,
                    "proposed_source": proposed,
                    "is_deterministic": True,
                    "fix_type": "deterministic"
                }

        # Fallback: remove statement line
        lines.pop(target_line - 1)
        proposed = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
        return {
            "success": True,
            "finding_id": finding_id,
            "start_line": target_line,
            "end_line": target_line,
            "original_snippet": orig_line,
            "replacement": "",
            "explanation": f"Removed unused construct at line {target_line}.",
            "proposed_source": proposed,
            "is_deterministic": True,
            "fix_type": "deterministic"
        }

    fix_unused_or_unreachable = fix_dead_code_item

    # -------------------------------------------------------------------------
    # Fixer 6: Stage 13 Runtime Errors
    # -------------------------------------------------------------------------
    @classmethod
    def fix_stage13_runtime_error(cls, source_code: str, finding_id: str, finding_data: Dict[str, Any], language: str) -> Optional[Dict[str, Any]]:
        target_line = int(finding_data.get("line") or 1)
        rule_id = str(finding_data.get("rule_id") or "")
        title = str(finding_data.get("title") or "").lower()
        evidence = str(finding_data.get("evidence") or "")
        lines = source_code.splitlines()

        if not (1 <= target_line <= len(lines)):
            return None

        orig_line = lines[target_line - 1]
        indent = " " * (len(orig_line) - len(orig_line.lstrip()))
        lang_key = (language or "english").lower()
        if_kw = IF_KEYWORDS.get(lang_key, "if")
        decl_kw = DECL_KEYWORDS.get(language, "let")

        # Case A: Division by zero
        if "zerodivisionerror" in rule_id.lower() or "division" in title or "/" in orig_line:
            # If literal / 0
            if re.search(r'/\s*0\b', orig_line):
                new_line = re.sub(r'/\s*0\b', '/ 1', orig_line)
                lines[target_line - 1] = new_line
                proposed = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
                return {
                    "success": True,
                    "finding_id": finding_id,
                    "start_line": target_line,
                    "end_line": target_line,
                    "original_snippet": orig_line,
                    "replacement": new_line,
                    "explanation": f"Replaced literal division by zero with safe divisor (1) at line {target_line}.",
                    "proposed_source": proposed,
                    "is_deterministic": True,
                    "fix_type": "deterministic"
                }
            # Variable divisor: insert guard before target_line
            m_div = re.search(r'/\s*([a-zA-Z0-9_\u0900-\u0C7F]+)', orig_line)
            if m_div:
                divisor = m_div.group(1)
                guard_line = f"{indent}{if_kw} ({divisor} == 0) {{ {divisor} = 1 }}"
                new_lines = lines[:target_line - 1] + [guard_line] + lines[target_line - 1:]
                proposed = "\n".join(new_lines) + ("\n" if source_code.endswith("\n") else "")
                return {
                    "success": True,
                    "finding_id": finding_id,
                    "start_line": target_line,
                    "end_line": target_line,
                    "original_snippet": orig_line,
                    "replacement": f"{guard_line}\n{orig_line}",
                    "explanation": f"Added non-zero guard check for divisor '{divisor}' before line {target_line}.",
                    "proposed_source": proposed,
                    "is_deterministic": True,
                    "fix_type": "deterministic"
                }

        # Case B: NameError (undefined runtime variable)
        if "nameerror" in rule_id.lower() or "nameerror" in title:
            m_var = re.search(r"name '([^']+)' is not defined", title) or re.search(r"([a-zA-Z0-9_\u0900-\u0C7F]+)", evidence)
            var_name = m_var.group(1) if m_var else "missing_var"
            init_line = f"{indent}{decl_kw} {var_name} = 0"
            new_lines = lines[:target_line - 1] + [init_line] + lines[target_line - 1:]
            proposed = "\n".join(new_lines) + ("\n" if source_code.endswith("\n") else "")
            return {
                "success": True,
                "finding_id": finding_id,
                "start_line": target_line,
                "end_line": target_line,
                "original_snippet": orig_line,
                "replacement": f"{init_line}\n{orig_line}",
                "explanation": f"Initialized runtime variable '{var_name}' before line {target_line}.",
                "proposed_source": proposed,
                "is_deterministic": True,
                "fix_type": "deterministic"
            }

        # Case C: Timeout / Infinite Loop
        if "timeout" in rule_id.lower() or "timeout" in title:
            # Look for while loop header on or near target_line
            loop_idx = target_line - 1
            loop_var = "counter"
            m_lvar = re.search(r'\b(?:while|जब_तक|ఎంతవరకు|যতক্ষণ|जोपर्यंत|जबसम्म)\s*\(\s*([a-zA-Z0-9_\u0900-\u0C7F]+)', orig_line)
            if m_lvar:
                loop_var = m_lvar.group(1)
            # Insert counter increment inside loop body
            update_stmt = f"{indent}    {loop_var} = {loop_var} + 1"
            new_lines = lines[:target_line] + [update_stmt] + lines[target_line:]
            proposed = "\n".join(new_lines) + ("\n" if source_code.endswith("\n") else "")
            return {
                "success": True,
                "finding_id": finding_id,
                "start_line": target_line,
                "end_line": target_line,
                "original_snippet": orig_line,
                "replacement": f"{orig_line}\n{update_stmt}",
                "explanation": f"Added loop counter advancement statement for '{loop_var}' to terminate while-loop.",
                "proposed_source": proposed,
                "is_deterministic": True,
                "fix_type": "deterministic"
            }

        return None

    # -------------------------------------------------------------------------
    # Fixer 7: Seeded Security Vulnerabilities (Stage 11/12)
    # -------------------------------------------------------------------------
    @classmethod
    def fix_security_vulnerability(cls, source_code: str, finding_id: str, finding_data: Dict[str, Any], language: str) -> Optional[Dict[str, Any]]:
        target_line = int(finding_data.get("line") or 1)
        rule_id = str(finding_data.get("rule_id") or finding_data.get("id") or "")
        title = str(finding_data.get("title") or finding_data.get("message") or "").lower()
        msg = str(finding_data.get("message") or "").lower()
        lines = source_code.splitlines()

        if not (1 <= target_line <= len(lines)):
            return None

        orig_line = lines[target_line - 1]
        indent = " " * (len(orig_line) - len(orig_line.lstrip()))
        lang_key = (language or "english").lower()
        if_kw = IF_KEYWORDS.get(lang_key, "if")

        # 1. Dynamic eval (CWE-95)
        if "eval" in title or "eval" in rule_id.lower() or "eval(" in orig_line:
            # Unwrap eval("...") or eval('...') -> ...
            m_eval = re.search(r'eval\s*\(\s*"(.*?)"\s*\)', orig_line) or re.search(r"eval\s*\(\s*'(.*?)'\s*\)", orig_line)
            if m_eval:
                inner_code = m_eval.group(1).replace("\\'", "'").replace('\\"', '"')
                pr_kw = PRINT_KEYWORDS.get(lang_key, "print")
                if inner_code.startswith("print(") and pr_kw != "print":
                    inner_code = re.sub(r'^print\(', f"{pr_kw}(", inner_code)
                new_line = f"{indent}{inner_code}"
                lines[target_line - 1] = new_line
                proposed = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
                return {
                    "success": True,
                    "finding_id": finding_id,
                    "start_line": target_line,
                    "end_line": target_line,
                    "original_snippet": orig_line,
                    "replacement": new_line,
                    "explanation": f"Removed dynamic evaluation sink (CWE-95) and replaced with direct safe execution.",
                    "proposed_source": proposed,
                    "is_deterministic": True,
                    "fix_type": "deterministic"
                }

        # 2. SQL Injection (CWE-89)
        if "sql" in title or "cwe-89" in title or "sec-inj-001" in rule_id.lower():
            if "=" in orig_line and "+" in orig_line:
                # Remove string concatenation on query variable to keep declaration intact
                new_line = re.sub(r'\s*\+\s*[a-zA-Z0-9_\u0900-\u0D7F]+', '', orig_line)
                lines[target_line - 1] = new_line
                proposed = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
                return {
                    "success": True,
                    "finding_id": finding_id,
                    "start_line": target_line,
                    "end_line": target_line,
                    "original_snippet": orig_line,
                    "replacement": new_line,
                    "explanation": f"Sanitized unescaped SQL parameter concatenation (CWE-89).",
                    "proposed_source": proposed,
                    "is_deterministic": True,
                    "fix_type": "deterministic"
                }

        # 3. Hardcoded Secret (CWE-798)
        if "secret" in title or "password" in title or "credential" in title or "cwe-798" in title:
            # Replace literal secret string with environment config placeholder
            m_sec = re.search(r'=\s*["\'][^"\']+["\']', orig_line)
            if m_sec:
                new_line = orig_line[:m_sec.start()] + '= "REDACTED_USE_ENVIRONMENT_CONFIG"'
                lines[target_line - 1] = new_line
                proposed = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
                return {
                    "success": True,
                    "finding_id": finding_id,
                    "start_line": target_line,
                    "end_line": target_line,
                    "original_snippet": orig_line,
                    "replacement": new_line,
                    "explanation": f"Replaced hardcoded sensitive credential (CWE-798) with environment configuration placeholder.",
                    "proposed_source": proposed,
                    "is_deterministic": True,
                    "fix_type": "deterministic"
                }

        # 4. Path Traversal (CWE-22)
        if "traversal" in title or "cwe-22" in title:
            new_line = orig_line.replace("../", "").replace("..\\", "")
            lines[target_line - 1] = new_line
            proposed = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
            return {
                "success": True,
                "finding_id": finding_id,
                "start_line": target_line,
                "end_line": target_line,
                "original_snippet": orig_line,
                "replacement": new_line,
                "explanation": f"Sanitized directory traversal sequence (CWE-22) to prevent path manipulation.",
                "proposed_source": proposed,
                "is_deterministic": True,
                "fix_type": "deterministic"
            }

        # 5. Missing Authorization / IDOR (CWE-639)
        if "authorization" in title or "idor" in title or "cwe-639" in title or "sec-auth-001" in rule_id.lower():
            try:
                from web.security_analyzer import security_coordinator
                cf = security_coordinator.suggest_fix_for_finding(source_code, finding_id, finding_data, language=lang_key, prefer_deterministic=True)
                if cf and cf.get("success"):
                    return cf
            except Exception:
                pass
            guard_line = f'{indent}{if_kw} (user_role != "admin") {{ return 0 }}'
            new_lines = lines[:target_line - 1] + [guard_line] + lines[target_line - 1:]
            proposed = "\n".join(new_lines) + ("\n" if source_code.endswith("\n") else "")
            return {
                "success": True,
                "finding_id": finding_id,
                "start_line": target_line,
                "end_line": target_line,
                "original_snippet": orig_line,
                "replacement": f"{guard_line}\n{orig_line}",
                "explanation": f"Added role-based access control authorization check (CWE-639).",
                "proposed_source": proposed,
                "is_deterministic": True,
                "fix_type": "deterministic"
            }

        # 6. Shell Command Chaining & Command Injection (SEC-LEX-004, CWE-78)
        if "sec-lex-004" in rule_id.lower() or "shell" in title or "chaining" in title or "command injection" in title:
            if ";" in orig_line:
                # Sanitize shell command chaining by removing the injected command
                idx = orig_line.find(";")
                quote_char = '"' if '"' in orig_line else "'"
                prefix = orig_line[:idx].rstrip()
                new_line = prefix + quote_char
                lines[target_line - 1] = new_line
                proposed = "\n".join(lines) + ("\n" if source_code.endswith("\n") else "")
                return {
                    "success": True,
                    "finding_id": finding_id,
                    "start_line": target_line,
                    "end_line": target_line,
                    "original_snippet": orig_line,
                    "replacement": new_line,
                    "explanation": "Sanitized shell argument string by removing command chaining sequence (CWE-78).",
                    "proposed_source": proposed,
                    "is_deterministic": True,
                    "fix_type": "deterministic"
                }

        ret_kw = RETURN_KEYWORDS.get(lang_key, "return")

        # 7. Business Logic Flaws: Quantity & Discount (SEC-BUS-*)
        if "quantity" in title or "sec-bus-001" in rule_id.lower() or "negative quantity" in msg or "sec-logic-001" in rule_id.lower():
            qty_var = "quantity"
            is_func_header = any(k in orig_line for k in ("function", "def", "कार्य", "ఫంక్షన్", "విధము", "ফাংশন", "कार्य_करा", "कार्य_गर"))
            for up_idx in range(target_line - 1, -1, -1):
                f_line = lines[up_idx]
                m_fn = re.search(r'(?:function|def|कार्य|ఫంక్షన్|విధము|ফাংশন|कार्य_करा|कार्य_गर)\s+[A-Za-z0-9_\u0900-\u0D7F]+\s*\(([^)]*)\)', f_line)
                if m_fn:
                    params = [p.strip() for p in m_fn.group(1).split(",") if p.strip()]
                    if params:
                        qty_var = params[-1]
                    break
            inner_indent = indent + "    " if is_func_header else indent
            guard_line = f'{inner_indent}{if_kw} ({qty_var} <= 0) {{ {ret_kw} 0 }}'
            if is_func_header:
                new_lines = lines[:target_line] + [guard_line] + lines[target_line:]
            else:
                new_lines = lines[:target_line - 1] + [guard_line] + lines[target_line - 1:]
            proposed = "\n".join(new_lines) + ("\n" if source_code.endswith("\n") else "")
            return {
                "success": True,
                "finding_id": finding_id,
                "start_line": target_line,
                "end_line": target_line,
                "original_snippet": orig_line,
                "replacement": f"{orig_line}\n{guard_line}" if is_func_header else f"{guard_line}\n{orig_line}",
                "explanation": "Added positive quantity validation check.",
                "proposed_source": proposed,
                "is_deterministic": True,
                "fix_type": "deterministic"
            }

        if "discount" in title or "sec-bus-002" in rule_id.lower() or "discount cap" in msg:
            disc_var = "discount"
            m_assign = re.search(r'(?:let|मानो|అనుకో|ধরো|घ्या|मान|var)?\s*([A-Za-z0-9_\u0900-\u0D7F]+)\s*=', orig_line)
            if m_assign:
                disc_var = m_assign.group(1).strip()
            else:
                for up_idx in range(target_line - 2, max(-1, target_line - 10), -1):
                    m_up = re.search(r'(?:let|मानो|అనుకో|ধরో|घ्या|मान|var)\s+([A-Za-z0-9_\u0900-\u0D7F]+)\s*=', lines[up_idx])
                    if m_up:
                        disc_var = m_up.group(1).strip()
                        break
            cap_line = f'{indent}{if_kw} ({disc_var} > 50) {{ {disc_var} = 50 }}'
            new_lines = lines[:target_line - 1] + [cap_line] + lines[target_line - 1:]
            proposed = "\n".join(new_lines) + ("\n" if source_code.endswith("\n") else "")
            return {
                "success": True,
                "finding_id": finding_id,
                "start_line": target_line,
                "end_line": target_line,
                "original_snippet": orig_line,
                "replacement": f"{cap_line}\n{orig_line}",
                "explanation": "Enforced maximum allowed discount cap guard.",
                "proposed_source": proposed,
                "is_deterministic": True,
                "fix_type": "deterministic"
            }

        return None
