# -*- coding: utf-8 -*-
"""
tests/test_clean_demos_zero_diagnostics.py — Verification of Clean Demos and Security Invariants.

Asserts:
1. Zero diagnostics across all 45 clean demos (examples/<language>/*.vital, excluding security_lab):
   - lexer warnings == []
   - parser/semantic issues == []
   - Stage 11 findings == []
   - Code Health errors == []
   - dead_code.items == []
   - insecure_percentage == 0
   - health status == 'healthy'
   - final status == 'COMPLETED' (AI toggle off => Stage 12 skipped cleanly)
   - raw bytes contain no non-ASCII punctuation or digits in code positions
2. Positive tests in all 7 languages (english, hindi, telugu, bengali, marathi, nepali, fusion):
   - Homoglyph in code position still warns (Low severity, SEC-LEX-002 / SEC-LEX-003)
   - Homoglyph inside comment or string literal produces zero warnings
   - Real infinite loop raises SEC-RUN-001
   - tests/test_security_lab.py passes 100%
"""

import os
import sys
import glob
import re
import unittest
import hashlib
import uuid

# Ensure root and src are on sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from web.pipeline_tracker import PipelineRunTracker, execute_pipeline_with_tracker
from web.code_health import analyze_health
from web.security_analyzer import DeterministicSecurityScanner
from main import Compiler


def get_clean_demo_files():
    """Returns sorted list of all 45 clean demo files across the 7 language folders."""
    examples_dir = os.path.join(ROOT_DIR, "examples")
    pattern = os.path.join(examples_dir, "*", "*.vital")
    all_files = glob.glob(pattern)
    clean_files = [
        f for f in all_files
        if "security_lab" not in f.replace("\\", "/")
        and "saved" not in f.replace("\\", "/")
    ]
    return sorted(clean_files)


# Prohibited non-ASCII punctuation and Indic digits in code positions
INDIC_DIGITS = set(
    [chr(c) for c in range(0x0966, 0x0970)] +  # Devanagari ०-९
    [chr(c) for c in range(0x09E6, 0x09F0)] +  # Bengali ০-৯
    [chr(c) for c in range(0x0C66, 0x0C70)]    # Telugu ౦-౯
)

PROHIBITED_PUNCTUATION = {
    '\u0964',  # Devanagari danda ।
    '\u0965',  # Devanagari double danda ॥
    '\u0903',  # Devanagari visarga ः
    '\u0983',  # Bengali visarga ঃ
    '\u0C03',  # Telugu visarga ః
    '\u2018',  # Left single curly quote ‘
    '\u2019',  # Right single curly quote ’
    '\u201C',  # Left double curly quote “
    '\u201D',  # Right double curly quote ”
    '\u00A0',  # Non-breaking space
    '\u200B',  # Zero-width space
    '\u200C',  # Zero-width non-joiner
    '\u200D',  # Zero-width joiner
}


def find_prohibited_characters_in_code_positions(source_code: str):
    """
    Scans source code line by line and identifies any prohibited non-ASCII
    punctuation or Indic digits that appear strictly in CODE positions
    (i.e. excluding string literals and // comments).
    """
    violations = []
    pattern = r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\r\n]*)'
    for line_no, line in enumerate(source_code.splitlines(), start=1):
        parts = re.split(pattern, line)
        col_offset = 1
        for idx, part in enumerate(parts):
            if idx % 2 == 0 and part:  # Code position
                for char_idx, char in enumerate(part):
                    if char in PROHIBITED_PUNCTUATION or char in INDIC_DIGITS:
                        violations.append({
                            "line": line_no,
                            "column": col_offset + char_idx,
                            "char": char,
                            "codepoint": f"U+{ord(char):04X}",
                            "context": part.strip()
                        })
            col_offset += len(part)
    return violations


class TestCleanDemosZeroDiagnostics(unittest.TestCase):
    """Suite 1: Assert all 45 clean demos produce strictly zero diagnostics."""

    @classmethod
    def setUpClass(cls):
        cls.demo_files = get_clean_demo_files()
        assert len(cls.demo_files) == 45, f"Expected 45 clean demo files, found {len(cls.demo_files)}"

    def test_file_count(self):
        """Verify all 45 expected clean demo files exist."""
        self.assertEqual(len(self.demo_files), 45)

    def test_all_clean_demos_produce_zero_diagnostics(self):
        """
        Runs the 14-stage pipeline and Code Health analyzer on every clean demo.
        Asserts zero diagnostics, 0% insecure, healthy status, and COMPLETED final status.
        """
        failures = []

        for fpath in self.demo_files:
            rel_name = os.path.relpath(fpath, ROOT_DIR).replace("\\", "/")
            with self.subTest(file=rel_name):
                with open(fpath, "r", encoding="utf-8") as f:
                    source_code = f.read()

                # 1. Raw bytes inspection: no prohibited punctuation or Indic digits in code positions
                violations = find_prohibited_characters_in_code_positions(source_code)
                self.assertEqual(
                    violations, [],
                    f"[{rel_name}] Found prohibited non-ASCII characters in code positions: {violations}"
                )

                # 2. Code Health analyzer inspection
                health = analyze_health(source_code, filename=os.path.basename(fpath))
                
                # Code Health errors == []
                health_errors = [
                    item for item in health.get("issues", [])
                    if item.get("severity") in ("error", "critical")
                ]
                self.assertEqual(
                    health_errors, [],
                    f"[{rel_name}] Code Health produced error/critical issues: {health_errors}"
                )

                # dead_code.items == []
                dead_items = health.get("metrics", {}).get("dead_code", {}).get("items", [])
                self.assertEqual(
                    dead_items, [],
                    f"[{rel_name}] Code Health reported dead code items: {dead_items}"
                )

                # insecure_percentage == 0
                insecure_pct = health.get("security", {}).get("insecure_percentage", 0.0)
                self.assertEqual(
                    insecure_pct, 0.0,
                    f"[{rel_name}] Code Health insecure_percentage must be 0, got {insecure_pct}"
                )

                # health status 'healthy'
                health_status = health.get("status")
                self.assertEqual(
                    health_status, "healthy",
                    f"[{rel_name}] Code Health status must be 'healthy', got '{health_status}'"
                )

                # 3. 14-stage Pipeline Execution (AI toggle OFF)
                source_hash = hashlib.sha256(source_code.encode("utf-8")).hexdigest()
                tracker = PipelineRunTracker(run_id=str(uuid.uuid4()), source_hash=source_hash)
                result = execute_pipeline_with_tracker(
                    source_code=source_code,
                    tracker=tracker,
                    run_ai_security=False
                )

                stages = result.stages

                # Lexer warnings == []
                st2 = stages.get("lexical_analysis", {})
                self.assertEqual(st2.get("findings_count", 0), 0, f"[{rel_name}] Stage 2 had findings: {st2}")
                self.assertIn(st2.get("status"), ("passed", "completed"), f"[{rel_name}] Stage 2 status was {st2.get('status')}")

                # Parser / Semantic == []
                st3 = stages.get("syntax_analysis", {})
                st4 = stages.get("ast_construction", {})
                st5 = stages.get("semantic_analysis", {})
                self.assertEqual(st3.get("findings_count", 0), 0, f"[{rel_name}] Stage 3 had findings: {st3}")
                self.assertIn(st3.get("status"), ("passed", "completed"), f"[{rel_name}] Stage 3 failed")
                self.assertEqual(st4.get("findings_count", 0), 0, f"[{rel_name}] Stage 4 had findings: {st4}")
                self.assertIn(st4.get("status"), ("passed", "completed"), f"[{rel_name}] Stage 4 failed")
                self.assertEqual(st5.get("findings_count", 0), 0, f"[{rel_name}] Stage 5 had findings: {st5}")
                self.assertIn(st5.get("status"), ("passed", "completed"), f"[{rel_name}] Stage 5 failed")

                # Stage 11 findings == []
                st11 = stages.get("security_analysis", {})
                self.assertEqual(st11.get("findings_count", 0), 0, f"[{rel_name}] Stage 11 had findings: {st11}")
                self.assertIn(st11.get("status"), ("passed", "completed"), f"[{rel_name}] Stage 11 failed")

                # Stage 12 skipped by user (not a warning/failure)
                st12 = stages.get("ai_security_analysis", {})
                self.assertEqual(st12.get("status"), "skipped", f"[{rel_name}] Stage 12 status was {st12.get('status')}")

                # Final status COMPLETED
                overall_status = result.compute_overall_status()
                self.assertEqual(
                    overall_status, "COMPLETED",
                    f"[{rel_name}] Pipeline final status must be COMPLETED, got '{overall_status}'"
                )


class TestPositiveSecurityInvariants(unittest.TestCase):
    """
    Suite 2: Positive tests across all 7 languages:
    - Homoglyph in code position still warns (Low severity, SEC-LEX-002 / SEC-LEX-003)
    - Homoglyph in comment or string literal produces zero warnings
    - Infinite loop raises SEC-RUN-001
    - Security Lab suite passes 100%
    """

    LANGUAGES = ["english", "hindi", "telugu", "bengali", "marathi", "nepali", "fusion"]

    # Code snippets with homoglyph in code position (Cyrillic 'а' U+0430 or Devanagari '।' U+0964)
    HOMOGLYPH_CODE_SNIPPETS = {
        "english": 'let v\u0430r_x = 10;',
        "hindi": 'मान संख्य\u0430 = 10;',
        "telugu": 'లెట్ x\u0430 = 10;',
        "bengali": 'লেট x\u0430 = 10;',
        "marathi": 'मान x\u0430 = 10;',
        "nepali": 'मान x\u0430 = 10;',
        "fusion": 'let x\u0430 = 10;'
    }

    # Code snippets with homoglyph inside comment
    HOMOGLYPH_COMMENT_SNIPPETS = {
        "english": '// Variable name note with Cyrillic а: v\u0430r_x\nlet x = 10;',
        "hindi": '// टिप्पणी: मान संख्या ।\nमान x = 10;',
        "telugu": '// వ్యాఖ్య: x\u0430 మరియు \u0964\nలెట్ x = 10;',
        "bengali": '// মন্তব্য: x\u0430 এবং \u0964\nলেট x = 10;',
        "marathi": '// टिप्पणी: x\u0430 आणि \u0964\nमान x = 10;',
        "nepali": '// टिप्पणी: x\u0430 र \u0964\nमान x = 10;',
        "fusion": '// Fusion comment with lookalikes: x\u0430 and \u0964\nlet x = 10;'
    }

    # Code snippets with homoglyph inside string literal
    HOMOGLYPH_STRING_SNIPPETS = {
        "english": 'let label = "Result: v\u0430r_x | \u0964";',
        "hindi": 'मान संदेश = "गणना समाप्त \u0964 संख्य\u0430 = १०";',
        "telugu": 'లెట్ సందేశం = "ముగిసింది \u0964 x\u0430";',
        "bengali": 'লেট বার্তা = "গণনা সম্পন্ন \u0964 x\u0430";',
        "marathi": 'मान संदेश = "हिशोब पूर्ण \u0964 x\u0430";',
        "nepali": 'मान सन्देश = "गणना सकियो \u0964 x\u0430";',
        "fusion": 'let message = "Complete \u0964 and संख्य\u0430";'
    }

    # Unbounded infinite loops across all 7 languages
    INFINITE_LOOP_SNIPPETS = {
        "english": 'while (1) { print("spinning"); }',
        "hindi": 'जबतक (1) { बोल("लूप"); }',
        "telugu": 'ఉన్నంతవరకు (1) { చెప్పు("లూప్"); }',
        "bengali": 'যতক্ষণ (1) { বলো("লুপ"); }',
        "marathi": 'जोपर्यंत (1) { दाखवा("लूप"); }',
        "nepali": 'जबसम्म (1) { भन("लूप"); }',
        "fusion": 'while (1) { बोल("लूप"); }'
    }

    def test_homoglyph_in_code_position_warns_all_languages(self):
        """A homoglyph in code position must trigger a Low severity lexer warning across all 7 languages."""
        for lang in self.LANGUAGES:
            code = self.HOMOGLYPH_CODE_SNIPPETS[lang]
            findings = DeterministicSecurityScanner.scan_lexical(code, include_homoglyphs=True)
            homo_findings = [f for f in findings if f.rule_id in ("SEC-LEX-002", "SEC-LEX-003")]
            self.assertTrue(
                len(homo_findings) > 0,
                f"[{lang}] Expected homoglyph warning for code position snippet, found none"
            )
            for f in homo_findings:
                self.assertEqual(
                    f.severity, "Low",
                    f"[{lang}] Homoglyph warning severity must be Low, got {f.severity}"
                )

    def test_homoglyph_in_comment_does_not_warn_all_languages(self):
        """The same homoglyph inside a comment must produce ZERO warnings across all 7 languages."""
        for lang in self.LANGUAGES:
            snippet = self.HOMOGLYPH_COMMENT_SNIPPETS[lang]
            findings = DeterministicSecurityScanner.scan_lexical(snippet, include_homoglyphs=True)
            homo_findings = [f for f in findings if f.rule_id in ("SEC-LEX-002", "SEC-LEX-003")]
            self.assertEqual(
                homo_findings, [],
                f"[{lang}] Homoglyph inside comment must not warn, got: {homo_findings}"
            )

    def test_homoglyph_in_string_literal_does_not_warn_all_languages(self):
        """The same homoglyph inside a string literal must produce ZERO warnings across all 7 languages."""
        for lang in self.LANGUAGES:
            snippet = self.HOMOGLYPH_STRING_SNIPPETS[lang]
            findings = DeterministicSecurityScanner.scan_lexical(snippet, include_homoglyphs=True)
            homo_findings = [f for f in findings if f.rule_id in ("SEC-LEX-002", "SEC-LEX-003")]
            self.assertEqual(
                homo_findings, [],
                f"[{lang}] Homoglyph inside string literal must not warn, got: {homo_findings}"
            )

    def test_infinite_loop_raises_sec_run_001_all_languages(self):
        """Unbounded infinite loop raises SEC-RUN-001 across all 7 languages."""
        for lang in self.LANGUAGES:
            snippet = self.INFINITE_LOOP_SNIPPETS[lang]
            findings = DeterministicSecurityScanner.scan_execution_boundary(snippet)
            loop_findings = [f for f in findings if f.rule_id == "SEC-RUN-001"]
            self.assertTrue(
                len(loop_findings) > 0,
                f"[{lang}] Expected SEC-RUN-001 for infinite loop snippet, got none"
            )
            for f in loop_findings:
                self.assertEqual(f.severity, "High")

    def test_security_lab_suite_passes_100_percent(self):
        """Asserts tests/test_security_lab.py passes 100%."""
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "unittest", "tests/test_security_lab.py"],
            capture_output=True,
            text=True,
            cwd=ROOT_DIR
        )
        self.assertEqual(
            result.returncode, 0,
            f"test_security_lab.py failed:\n{result.stderr}\n{result.stdout}"
        )


if __name__ == "__main__":
    unittest.main()
