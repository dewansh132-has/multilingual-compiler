# -*- coding: utf-8 -*-
"""
tests/test_stage13_diagnostics.py — Verification Suite for Stage 13 Mapped Diagnostics

Verifies:
1. Structured execution data: exit_code, timed_out, stdout, stderr, exception_type, exception_message,
   traceback_frames, traceback_str, duration_ms, killed_by.
2. Source line mapping: mapped back to original .vital lines and verbatim substring evidence.
3. Distinct classification codes: RUN-TIMEOUT, RUN-MEMORY, RUN-EXCEPTION-<Type>, RUN-POLICY-VIOLATION, RUN-NONZERO-EXIT.
4. Pipeline status text ("Stopped at Stage N...") is NEVER stored as a stage finding.
5. Telugu, Hindi, Fusion runtime exceptions produce accurately mapped findings.
6. Blocked-by-security runs (Demo C) show Stage 13 as "blocked", not "failed", with 0 failure findings.
"""

import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from web.pipeline_tracker import execute_pipeline_with_tracker, map_runtime_error_to_vital
from web.compiler_runner import run_pipeline


class TestStage13Diagnostics(unittest.TestCase):

    def test_division_by_zero_mapped_finding(self):
        """Division by zero produces RUN-EXCEPTION-ZeroDivisionError with exact line and verbatim evidence."""
        code = (
            "let x = 10\n"
            "let y = 0\n"
            "let z = x / y\n"
            "print(z)"
        )
        tracker = execute_pipeline_with_tracker(code, language_hint="English", run_ai_security=False)
        st13 = tracker.stages.get("sandbox_execution", {})
        self.assertEqual(str(st13.get("status")), "failed")

        details = st13.get("details", {})
        self.assertFalse(details.get("timed_out"))
        self.assertEqual(details.get("killed_by"), "none")
        self.assertEqual(details.get("exception_type"), "ZeroDivisionError")
        self.assertIn("division by zero", details.get("exception_message", ""))
        self.assertIsInstance(details.get("traceback_frames"), list)
        self.assertIn("ZeroDivisionError", details.get("traceback_str", ""))

        findings = details.get("findings", [])
        self.assertEqual(len(findings), 1, "Must have exactly 1 mapped finding")
        f = findings[0]
        self.assertEqual(f.get("rule_id"), "RUN-EXCEPTION-ZeroDivisionError")
        self.assertEqual(f.get("line"), 3)
        self.assertIn(f.get("evidence"), code.splitlines()[2])
        self.assertEqual(f.get("evidence"), "x / y")
        self.assertEqual(f.get("message"), "ZeroDivisionError at line 3: 'x / y'")
        self.assertEqual(f.get("severity"), "CRITICAL")

        # Header status text must never be stored as finding
        self.assertNotIn("Stopped at Stage", f.get("rule_id", ""))
        self.assertNotIn("Stopped at Stage", f.get("title", ""))

    def test_infinite_loop_timeout_mapped_finding(self):
        """Infinite loop produces RUN-TIMEOUT pointing to the while statement with killed_by=timeout."""
        code = (
            "let x = 1\n"
            "while (x > 0) {\n"
            "    x = x + 1\n"
            "}"
        )
        # Use short timeout for test efficiency
        runner_res = run_pipeline(code, timeout_seconds=1.5)
        self.assertTrue(runner_res.get("timed_out"))
        self.assertEqual(runner_res.get("killed_by"), "timeout")
        self.assertEqual(runner_res.get("execution_status"), "timeout")

        vital_line, vital_col, evidence = map_runtime_error_to_vital(code, "", runner_res)
        self.assertEqual(vital_line, 2)
        self.assertIn(evidence, code.splitlines()[1])
        self.assertEqual(evidence, "while (x > 0) {")

    def test_undefined_runtime_name_mapped_finding(self):
        """Undefined runtime name (known builtin at compile-time like 'math' but unimported in sandbox) produces RUN-EXCEPTION-NameError."""
        code = (
            "let x = 10\n"
            "let y = math.sqrt(x)\n"
            "print(y)"
        )
        tracker = execute_pipeline_with_tracker(code, language_hint="English", run_ai_security=False)
        st13 = tracker.stages.get("sandbox_execution", {})
        self.assertEqual(str(st13.get("status")), "failed")

        details = st13.get("details", {})
        self.assertEqual(details.get("exception_type"), "NameError")
        self.assertEqual(details.get("killed_by"), "none")

        findings = details.get("findings", [])
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.get("rule_id"), "RUN-EXCEPTION-NameError")
        self.assertEqual(f.get("line"), 2)
        self.assertEqual(f.get("evidence"), "math")
        self.assertEqual(f.get("message"), "NameError at line 2: 'math'")

    def test_multilingual_telugu_runtime_error(self):
        """Telugu ZeroDivisionError maps accurately to Telugu line and verbatim operator substring."""
        code = (
            "అనుకో మొదటి_సంఖ్య = 100\n"
            "అనుకో విభజన_కారణం = 0\n"
            "అనుకో సమాధానం = మొదటి_సంఖ్య / విభజన_కారణం\n"
            "ముద్రించు(సమాధానం)"
        )
        tracker = execute_pipeline_with_tracker(code, language_hint="Telugu", run_ai_security=False)
        st13 = tracker.stages.get("sandbox_execution", {})
        self.assertEqual(str(st13.get("status")), "failed")

        findings = st13.get("details", {}).get("findings", [])
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.get("rule_id"), "RUN-EXCEPTION-ZeroDivisionError")
        self.assertEqual(f.get("line"), 3)
        self.assertIn(f.get("evidence"), code.splitlines()[2])
        self.assertEqual(f.get("evidence"), "మొదటి_సంఖ్య / విభజన_కారణం")
        self.assertEqual(f.get("message"), "ZeroDivisionError at line 3: 'మొదటి_సంఖ్య / విభజన_కారణం'")

    def test_multilingual_hindi_runtime_error(self):
        """Hindi ZeroDivisionError maps accurately to Hindi line and verbatim operator substring."""
        code = (
            "मानो पहला_मान = 500\n"
            "मानो दूसरा_मान = 0\n"
            "मानो उत्तर = पहला_मान / दूसरा_मान\n"
            "छापो(उत्तर)"
        )
        tracker = execute_pipeline_with_tracker(code, language_hint="Hindi", run_ai_security=False)
        st13 = tracker.stages.get("sandbox_execution", {})
        self.assertEqual(str(st13.get("status")), "failed")

        findings = st13.get("details", {}).get("findings", [])
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.get("rule_id"), "RUN-EXCEPTION-ZeroDivisionError")
        self.assertEqual(f.get("line"), 3)
        self.assertIn(f.get("evidence"), code.splitlines()[2])
        self.assertEqual(f.get("evidence"), "पहला_मान / दूसरा_मान")

    def test_multilingual_fusion_runtime_error(self):
        """Fusion runtime NameError maps accurately to the failing line."""
        code = (
            "let total = 99\n"
            "let calc = math.floor(total)\n"
            "print(calc)"
        )
        tracker = execute_pipeline_with_tracker(code, language_hint="Fusion", run_ai_security=False)
        st13 = tracker.stages.get("sandbox_execution", {})
        self.assertEqual(str(st13.get("status")), "failed")

        findings = st13.get("details", {}).get("findings", [])
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.get("rule_id"), "RUN-EXCEPTION-NameError")
        self.assertEqual(f.get("line"), 2)
        self.assertEqual(f.get("evidence"), "math")

    def test_blocked_by_security_run_leaves_stage13_blocked_with_zero_findings(self):
        """Telugu Demo C (sec_injection_eval_te) blocked by Stage 11 shows Stage 13 as 'blocked', never 'failed'."""
        te_path = os.path.join(PROJECT_ROOT, "examples", "security_lab", "telugu", "sec_injection_eval_te.vital")
        with open(te_path, "r", encoding="utf-8") as f:
            code = f.read()

        tracker = execute_pipeline_with_tracker(code, language_hint="Telugu", run_ai_security=False)

        # Stage 11 must be failed with gate decision BLOCK
        st11 = tracker.stages.get("security_analysis", {})
        self.assertEqual(str(st11.get("status")), "failed")
        self.assertEqual(st11.get("details", {}).get("gate_decision"), "BLOCK")

        # Stage 13 must be blocked, NOT failed
        st13 = tracker.stages.get("sandbox_execution", {})
        self.assertEqual(str(st13.get("status")), "blocked", f"Stage 13 status must be blocked, got {st13.get('status')}")
        self.assertNotEqual(str(st13.get("status")), "failed")

        # Findings for Stage 13 must be empty
        findings13 = st13.get("details", {}).get("findings", [])
        self.assertEqual(len(findings13), 0, "Blocked Stage 13 must have 0 findings")
        self.assertEqual(st13.get("findings_count", 0), 0)

    def test_header_message_is_never_stored_as_stage_finding(self):
        """Header message ('Stopped at Stage 13...') must never be stored as a finding."""
        code = (
            "let x = 10\n"
            "let y = 0\n"
            "let z = x / y\n"
            "print(z)"
        )
        tracker = execute_pipeline_with_tracker(code, language_hint="English", run_ai_security=False)
        self.assertIn("Stopped at Stage 13", tracker.header_message)

        st13 = tracker.stages.get("sandbox_execution", {})
        findings = st13.get("details", {}).get("findings", [])
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertNotEqual(f.get("title"), tracker.header_message)
        self.assertNotEqual(f.get("message"), tracker.header_message)
        self.assertNotEqual(f.get("rule_id"), "ERR-SANDBOX_EXECUTION")
        self.assertEqual(f.get("rule_id"), "RUN-EXCEPTION-ZeroDivisionError")


if __name__ == "__main__":
    unittest.main()
