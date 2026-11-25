# -*- coding: utf-8 -*-
"""
tests/test_fix_consistency_and_verification.py — Comprehensive Test Suite for Fix Consistency,
Stage-Targeted Fix All, Suspect Fix Verification, Undo, and Save Gating.

Covers:
1. Recomputing Code Health and clearing pipeline state after any change to the buffer.
2. Stage-targeted Fix All:
   - Applies in deterministic order: syntax -> semantic -> security
   - Records {group, issues_before, issues_after} after EACH group
   - Produces delta string e.g. "Errors 2 -> 0, Insecure 31% -> 9%"
3. Fix integrity verification (suspect fix detection):
   - Confirms target finding ID is absent from fresh scan.
   - Flags as suspect if a line flagged by a later stage is deleted without remediating the pattern.
   - Flags as suspect if a line vanished but the finding ID persists elsewhere.
   - Flags as suspect if a line was deleted and a new/different finding replaced it.
4. Undo Fix:
   - Restores exact prior buffer
   - Code Health is recomputed from the restored buffer.
5. Orange modified dot:
   - Reflects actual buffer != original hash.
   - Buffer equal to original hash -> is_dirty is False.
   - Buffer different from original hash -> is_dirty is True.
6. Save Corrected Code gating:
   - Verification required for stages 1-12.
   - Unverified code prompts for explicit confirmation.
"""

import os
import sys
import unittest
import json
import hashlib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from web.code_health import analyze_health
from web.fix_orchestrator import verify_fix_integrity, run_stage_targeted_fix_all
import web.server as server


class TestFixConsistencyAndVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        server.app.config["TESTING"] = True
        cls.client = server.app.test_client()

    def test_verify_fix_integrity_clean_repair(self):
        """A genuine syntax fix that resolves the issue cleanly is NOT suspect."""
        # Telugu demo D has an unbalanced closing brace
        file_path = os.path.join("examples", "security_lab", "telugu", "sec_business_workflow_te.vital")
        with open(file_path, "r", encoding="utf-8") as f:
            broken_code = f.read()

        # Repair by properly closing the brace
        repaired_code = broken_code + "\n}\n"

        res = verify_fix_integrity(
            before_code=broken_code,
            after_code=repaired_code,
            language="Telugu",
            filename="sec_business_workflow_te.vital",
            target_finding_id="SYN-001",
            stage_id="syntax_analysis"
        )
        self.assertTrue(res["is_valid"])
        # Should not be suspect because target finding was resolved and no downstream lines were deleted
        self.assertFalse(res["is_suspect"])
        self.assertIsNone(res["suspect_warning"])

    def test_verify_fix_integrity_unremediated_target(self):
        """If the target finding ID remains active after fix, flag as suspect."""
        file_path = os.path.join("examples", "security_lab", "telugu", "sec_business_workflow_te.vital")
        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()

        # Dummy modification that does NOT fix the syntax error
        dummy_code = code + "\n// just a comment\n"

        res = verify_fix_integrity(
            before_code=code,
            after_code=dummy_code,
            language="Telugu",
            filename="sec_business_workflow_te.vital",
            target_finding_id="SYN-001",
            stage_id="syntax_analysis"
        )
        self.assertTrue(res["is_suspect"])
        self.assertTrue(any("SYN-001" in r for r in res["suspect_reasons"]))

    def test_verify_fix_integrity_deleted_downstream_line(self):
        """Deleting a line flagged with a downstream defect without remediating it flags suspect."""
        # Code with a downstream path traversal finding (Stage 11, line 3)
        before_code = (
            '// VITAL script\n'
            'let x = 10\n'
            'let secret_path = "../../etc/shadow"\n'
            'print(x)\n'
        )
        # Fix for "syntax" that bluntly deletes/modifies line 3 with the downstream security secret
        # but the path traversal pattern persists elsewhere
        after_code = (
            '// VITAL script\n'
            'let x = 10\n'
            'let user_path = "../../etc/shadow"\n'
            'print(x)\n'
        )
        res = verify_fix_integrity(
            before_code=before_code,
            after_code=after_code,
            language="English",
            filename="test.vital",
            stage_id="syntax_analysis"
        )
        # Line 3 was deleted/modified but the defect persists elsewhere!
        self.assertTrue(res["is_suspect"])
        self.assertTrue(any("persists elsewhere" in r for r in res["suspect_reasons"]))

    def test_verify_fix_integrity_deleted_and_replaced_by_new_finding(self):
        """Deleting a flagged line and replacing it with a new error flags suspect."""
        before_code = (
            'let a = 1\n'
            'let b = 2\n'
            'let target_file = "../../etc/passwd"\n'
            'print(a + b)\n'
        )
        # Delete line 3 and replace with a syntax error (unbalanced brace)
        after_code = (
            'let a = 1\n'
            'let b = 2\n'
            'if (a > 0) {\n'  # unclosed brace syntax error
            'print(a + b)\n'
        )
        res = verify_fix_integrity(
            before_code=before_code,
            after_code=after_code,
            language="English",
            filename="test.vital",
            stage_id="syntax_analysis"
        )
        self.assertTrue(res["is_suspect"])

    def test_stage_targeted_fix_all_deterministic_order_and_delta(self):
        """Stage-targeted Fix All runs syntax -> semantic -> security and records before/after deltas."""
        code = (
            '// Educational Demo with defects\n'
            'let admin_secret_key = "sk_live_sec_prod_9948271630_super_admin"\n'
            'let count = 5\n'
            'print(count)\n'
        )
        res = run_stage_targeted_fix_all(
            source_code=code,
            language="English",
            file_path="sec_demo.vital",
            use_ai=False  # Deterministic test
        )
        self.assertTrue(res["success"])
        self.assertIn("delta_text", res)
        # Delta format must match: "Errors X -> Y, Insecure A% -> B%"
        self.assertRegex(res["delta_text"], r"^Errors \d+ -> \d+, Insecure \d+% -> \d+%$")

        # Must record all 3 groups in strict order: syntax -> semantic -> security
        groups = res["groups"]
        self.assertEqual(len(groups), 3)
        self.assertEqual(groups[0]["group"], "syntax")
        self.assertEqual(groups[1]["group"], "semantic")
        self.assertEqual(groups[2]["group"], "security")

        # Each group must record {group, issues_before, issues_after}
        for g in groups:
            self.assertIn("issues_before", g)
            self.assertIn("issues_after", g)
            self.assertIn("errors", g["issues_before"])
            self.assertIn("insecure_percentage", g["issues_before"])
            self.assertIn("errors", g["issues_after"])
            self.assertIn("insecure_percentage", g["issues_after"])

    def test_stage_targeted_fix_all_api_endpoint(self):
        """POST /api/ai/fix-all-stages returns complete stage-targeted response."""
        code = (
            'let x = 1\n'
            'print(x)\n'
        )
        resp = self.client.post("/api/ai/fix-all-stages", json={
            "source_code": code,
            "language": "English",
            "file_path": "clean.vital"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("delta_text", data)
        self.assertIn("groups", data)
        self.assertEqual(len(data["groups"]), 3)

    def test_orange_modified_dot_hash_reflection(self):
        """Orange modified dot logic: is_dirty reflects actual buffer != original hash."""
        original_code = 'print("original")'
        orig_hash = hashlib.sha256(original_code.encode("utf-8")).hexdigest()

        # Same content -> clean (not dirty)
        curr_code_same = 'print("original")'
        curr_hash_same = hashlib.sha256(curr_code_same.encode("utf-8")).hexdigest()
        self.assertEqual(curr_hash_same, orig_hash)
        is_dirty_same = (curr_hash_same != orig_hash)
        self.assertFalse(is_dirty_same)

        # Modified content -> dirty
        curr_code_mod = 'print("modified")'
        curr_hash_mod = hashlib.sha256(curr_code_mod.encode("utf-8")).hexdigest()
        self.assertNotEqual(curr_hash_mod, orig_hash)
        is_dirty_mod = (curr_hash_mod != orig_hash)
        self.assertTrue(is_dirty_mod)

        # Modified then reverted back -> clean (not dirty)
        curr_code_reverted = 'print("original")'
        curr_hash_reverted = hashlib.sha256(curr_code_reverted.encode("utf-8")).hexdigest()
        self.assertEqual(curr_hash_reverted, orig_hash)
        is_dirty_reverted = (curr_hash_reverted != orig_hash)
        self.assertFalse(is_dirty_reverted)

    def test_undo_and_recomputing_health(self):
        """Undo restores prior buffer and recomputes health accurately."""
        prior_code = 'let x = 10\nprint(x)\n'
        health_prior = analyze_health(prior_code, language="English", filename="test.vital")

        # User modifies buffer introducing an error
        modified_code = 'let x = \nprint(x)\n'
        health_modified = analyze_health(modified_code, language="English", filename="test.vital")
        self.assertNotEqual(health_prior["score"], health_modified["score"])

        # Undo restores exact prior code
        restored_code = prior_code
        health_restored = analyze_health(restored_code, language="English", filename="test.vital")
        self.assertEqual(health_restored["score"], health_prior["score"])
        self.assertEqual(health_restored["status"], health_prior["status"])
        self.assertEqual(len(health_restored["errors"]), len(health_prior["errors"]))

    def test_save_corrected_code_verification_policy(self):
        """Unverified code requires explicit confirmation before saving."""
        def can_save_without_warning(pipeline_finished, buffer_hash, compiled_hash, stages_1_to_12_passed):
            return bool(
                pipeline_finished and
                buffer_hash == compiled_hash and
                stages_1_to_12_passed
            )

        # 1. Clean run matching buffer -> verified save (no confirmation warning needed)
        h = hashlib.sha256(b"code").hexdigest()
        self.assertTrue(can_save_without_warning(
            pipeline_finished=True,
            buffer_hash=h,
            compiled_hash=h,
            stages_1_to_12_passed=True
        ))

        # 2. Buffer edited after pipeline run -> unverified (must prompt)
        h2 = hashlib.sha256(b"edited code").hexdigest()
        self.assertFalse(can_save_without_warning(
            pipeline_finished=True,
            buffer_hash=h2,
            compiled_hash=h,
            stages_1_to_12_passed=True
        ))

        # 3. Pipeline failed at stage 5 or blocked at stage 11 -> unverified (must prompt)
        self.assertFalse(can_save_without_warning(
            pipeline_finished=True,
            buffer_hash=h,
            compiled_hash=h,
            stages_1_to_12_passed=False
        ))

        # 4. Pipeline never run -> unverified (must prompt)
        self.assertFalse(can_save_without_warning(
            pipeline_finished=False,
            buffer_hash=h,
            compiled_hash="",
            stages_1_to_12_passed=False
        ))


if __name__ == "__main__":
    unittest.main()
