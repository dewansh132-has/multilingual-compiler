"""
tests/test_security_lab_contract.py — Contract Compliance Tests for all 28 Security Lab Demos

Contract specification:
- Demo A (sec_auth_account*): fails at Stage 5 (the one seeded undefined variable),
  nothing else wrong in stages 1-4.
- Demo D (sec_business_workflow*): fails at Stage 3 (the one seeded missing brace).
- Demo B (sec_data_config*) and Demo C (sec_injection_eval*): pass stages 1-10, fail at
  Stage 11 with their seeded CWEs, in ALL 7 languages including Fusion.
- Asserts that NO unseeded finding appears (e.g. no homoglyphs SEC-LEX-003, no unused-variable noise in stages 1-10).
"""

import os
import glob
import io
import contextlib
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEC_LAB_DIR = os.path.join(PROJECT_ROOT, "examples", "security_lab")

from web.pipeline_tracker import execute_pipeline_with_tracker, STAGE_ORDER


class TestSecurityLabContractCompliance(unittest.TestCase):
    """Parametrized contract verification across all 28 Security Lab fixtures."""

    LANGUAGES = ["english", "hindi", "telugu", "bengali", "marathi", "nepali", "fusion"]

    def _get_demo_path(self, lang: str, prefix: str) -> str:
        matches = glob.glob(os.path.join(SEC_LAB_DIR, lang, f"{prefix}*.vital"))
        self.assertTrue(len(matches) > 0, f"Demo file matching '{prefix}' missing in {lang}")
        return matches[0]

    def _execute_tracker(self, filepath: str):
        with open(filepath, "r", encoding="utf-8") as f:
            code = f.read()
        with contextlib.redirect_stdout(io.StringIO()):
            tracker = execute_pipeline_with_tracker(code, run_ai_security=False)
        return tracker, code

    # =========================================================================
    # DEMO A: Fails at Stage 5 (Semantic Analysis)
    # =========================================================================
    def test_demo_a_fails_at_stage_5_all_languages(self):
        """Demo A: fails at Stage 5 (the one seeded undefined variable), nothing else wrong in stages 1-4."""
        for lang in self.LANGUAGES:
            with self.subTest(language=lang):
                path = self._get_demo_path(lang, "sec_auth_account")
                tracker, _ = self._execute_tracker(path)

                # Stages 1-4 must pass cleanly with 0 findings
                for sid in ["source_input", "lexical_analysis", "syntax_analysis", "ast_construction"]:
                    st = tracker.stages.get(sid, {})
                    self.assertIn(str(st.get("status")), ("passed", "completed"),
                                  f"[{lang}] Stage {sid} should pass, got {st.get('status')}")
                    findings = st.get("details", {}).get("findings", []) or st.get("details", {}).get("diagnostics", [])
                    self.assertEqual(len(findings), 0,
                                     f"[{lang}] Stage {sid} should have 0 findings, got: {findings}")

                # Stage 5 must fail with the seeded undefined variable
                st5 = tracker.stages.get("semantic_analysis", {})
                self.assertEqual(str(st5.get("status")), "failed",
                                 f"[{lang}] Stage 5 must fail for Demo A, got: {st5.get('status')}")
                findings5 = st5.get("details", {}).get("findings", []) or st5.get("details", {}).get("diagnostics", [])
                self.assertGreater(len(findings5), 0, f"[{lang}] Stage 5 must have diagnostic findings")
                rule_ids = [f.get("rule_id") or f.get("id") or f.get("code") for f in findings5]
                self.assertIn("SEC-SEM-001", rule_ids, f"[{lang}] Demo A must report SEC-SEM-001")

                # Stages 6-14 must be blocked
                for sid in STAGE_ORDER[5:]:
                    st = tracker.stages.get(sid, {})
                    self.assertEqual(str(st.get("status")), "blocked",
                                     f"[{lang}] Downstream stage {sid} must be blocked")

    # =========================================================================
    # DEMO D: Fails at Stage 3 (Syntax Analysis)
    # =========================================================================
    def test_demo_d_fails_at_stage_3_all_languages(self):
        """Demo D: fails at Stage 3 (the one seeded missing brace), nothing wrong in stages 1-2."""
        for lang in self.LANGUAGES:
            with self.subTest(language=lang):
                path = self._get_demo_path(lang, "sec_business_workflow")
                tracker, _ = self._execute_tracker(path)

                # Stages 1-2 must pass cleanly with 0 findings
                for sid in ["source_input", "lexical_analysis"]:
                    st = tracker.stages.get(sid, {})
                    self.assertIn(str(st.get("status")), ("passed", "completed"),
                                  f"[{lang}] Stage {sid} should pass, got {st.get('status')}")
                    findings = st.get("details", {}).get("findings", [])
                    self.assertEqual(len(findings), 0,
                                     f"[{lang}] Stage {sid} should have 0 findings, got: {findings}")

                # Stage 3 must fail with missing delimiter
                st3 = tracker.stages.get("syntax_analysis", {})
                self.assertEqual(str(st3.get("status")), "failed",
                                 f"[{lang}] Stage 3 must fail for Demo D, got: {st3.get('status')}")
                findings3 = st3.get("details", {}).get("findings", []) or st3.get("details", {}).get("diagnostics", [])
                rule_ids = [f.get("rule_id") or f.get("id") or f.get("code") for f in findings3]
                self.assertTrue(any("PAR" in r or "SYN" in r or "DELIM" in r for r in rule_ids),
                                f"[{lang}] Stage 3 must report delimiter syntax flaw, got: {rule_ids}")

                # Stages 4-14 must be blocked
                for sid in STAGE_ORDER[3:]:
                    st = tracker.stages.get(sid, {})
                    self.assertEqual(str(st.get("status")), "blocked",
                                     f"[{lang}] Downstream stage {sid} must be blocked")

    # =========================================================================
    # DEMO B: Passes Stages 1-10, Blocks at Stage 11 (Security Analysis)
    # =========================================================================
    def test_demo_b_passes_stages_1_to_10_and_blocks_stage_11(self):
        """Demo B: passes stages 1-10 cleanly, fails at Stage 11 with seeded CWEs in ALL 7 languages."""
        for lang in self.LANGUAGES:
            with self.subTest(language=lang):
                path = self._get_demo_path(lang, "sec_data_config")
                tracker, _ = self._execute_tracker(path)

                # Stages 1-10 must pass cleanly with zero findings
                for sid in STAGE_ORDER[:10]:
                    st = tracker.stages.get(sid, {})
                    self.assertIn(str(st.get("status")), ("passed", "completed"),
                                  f"[{lang}] Stage {sid} must pass, got {st.get('status')}")
                    findings = st.get("details", {}).get("findings", []) or st.get("details", {}).get("diagnostics", [])
                    self.assertEqual(len(findings), 0,
                                     f"[{lang}] Stage {sid} should have 0 findings in Demo B, got: {findings}")

                # Stage 11 must trigger BLOCK gate decision
                st11 = tracker.stages.get("security_analysis", {})
                gate_decision = st11.get("details", {}).get("gate_decision")
                self.assertEqual(gate_decision, "BLOCK",
                                 f"[{lang}] Stage 11 gate decision must be BLOCK, got {gate_decision}")
                self.assertEqual(str(st11.get("status")), "failed",
                                 f"[{lang}] Stage 11 status must be failed (blocked)")

                # Seeded findings must include data/secret vulnerabilities
                findings11 = st11.get("details", {}).get("findings", [])
                rule_ids = [f.get("rule_id") or f.get("id") for f in findings11]
                self.assertTrue(any("DATA" in r for r in rule_ids),
                                f"[{lang}] Demo B must contain SEC-DATA findings, got: {rule_ids}")

                # No unseeded homoglyph finding
                self.assertNotIn("SEC-LEX-003", rule_ids,
                                 f"[{lang}] Demo B must not contain unseeded homoglyph warnings")

                # Stages 12-14 must be blocked
                for sid in STAGE_ORDER[11:]:
                    st = tracker.stages.get(sid, {})
                    self.assertEqual(str(st.get("status")), "blocked",
                                     f"[{lang}] Downstream stage {sid} must be blocked")

    # =========================================================================
    # DEMO C: Passes Stages 1-10, Blocks at Stage 11 (Security Analysis)
    # =========================================================================
    def test_demo_c_passes_stages_1_to_10_and_blocks_stage_11(self):
        """Demo C: passes stages 1-10, fails at Stage 11 with seeded CWEs in ALL 7 languages including Fusion."""
        for lang in self.LANGUAGES:
            with self.subTest(language=lang):
                path = self._get_demo_path(lang, "sec_injection_eval")
                tracker, _ = self._execute_tracker(path)

                # Stages 1-10 must all pass
                for sid in STAGE_ORDER[:10]:
                    st = tracker.stages.get(sid, {})
                    self.assertIn(str(st.get("status")), ("passed", "completed"),
                                  f"[{lang}] Stage {sid} must pass, got: {st.get('status')}")

                # Stages 3-10 must have zero findings (no semantic errors, no syntax errors)
                for sid in STAGE_ORDER[2:10]:
                    st = tracker.stages.get(sid, {})
                    findings = st.get("details", {}).get("findings", []) or st.get("details", {}).get("diagnostics", [])
                    self.assertEqual(len(findings), 0,
                                     f"[{lang}] Stage {sid} should have 0 findings in Demo C, got: {findings}")

                # Stage 11 must trigger BLOCK gate decision
                st11 = tracker.stages.get("security_analysis", {})
                gate_decision = st11.get("details", {}).get("gate_decision")
                self.assertEqual(gate_decision, "BLOCK",
                                 f"[{lang}] Stage 11 gate decision must be BLOCK, got {gate_decision}")
                self.assertEqual(str(st11.get("status")), "failed",
                                 f"[{lang}] Stage 11 status must be failed (blocked)")

                # Seeded findings must include SQL/Cmd/Eval injection
                findings11 = st11.get("details", {}).get("findings", [])
                rule_ids = [f.get("rule_id") or f.get("id") for f in findings11]
                self.assertIn("SEC-LEX-004", rule_ids, f"[{lang}] Demo C must contain SEC-LEX-004 (Cmd Injection)")
                self.assertIn("SEC-INJ-001", rule_ids, f"[{lang}] Demo C must contain SEC-INJ-001 (SQL Injection)")
                self.assertIn("SEC-IR-001", rule_ids, f"[{lang}] Demo C must contain SEC-IR-001 (Eval Sink)")

                # No unseeded homoglyph finding
                self.assertNotIn("SEC-LEX-003", rule_ids,
                                 f"[{lang}] Demo C must not contain unseeded homoglyph warnings")

                # Stages 12-14 must be blocked
                for sid in STAGE_ORDER[11:]:
                    st = tracker.stages.get(sid, {})
                    self.assertEqual(str(st.get("status")), "blocked",
                                     f"[{lang}] Downstream stage {sid} must be blocked")


if __name__ == "__main__":
    unittest.main()
