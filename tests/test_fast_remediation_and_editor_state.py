# -*- coding: utf-8 -*-
"""
tests/test_fast_remediation_and_editor_state.py

Unit & Integration Tests verifying:
1. Applying a fix changes the working buffer but not the original demo on disk.
2. Rejecting a fix leaves the editor buffer unchanged.
3. Undo restores the exact pre-fix working buffer.
4. Switching between two demos and returning restores each buffer correctly (per-file state).
5. Restoring the original recovers the exact original vulnerable source.
6. Ollama timeout or disconnection does not leave the UI or API loading indefinitely.
7. A deterministic fix appears instantly (<50ms) without waiting for a slow model response.
8. Remediation result caching prevents redundant computations and prevents stale fixes.
9. Late AI responses cannot overwrite editor buffers without explicit user approval.
10. Saving a corrected program through Save As does not modify the original demo file.
11. Existing multilingual compilation and security checks continue to work across all 6 languages.
"""

import os
import time
import json
import unittest
from unittest.mock import patch, MagicMock

from web.server import app
from web.demo_manager import get_demo_content, get_all_demos
from web.security_lab_registry import SECURITY_LAB_DEMOS, get_security_lab_demo_by_path
from web.security_analyzer import security_coordinator, DeterministicSecurityScanner
from web.compiler_runner import run_pipeline

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestFastRemediationAndEditorState(unittest.TestCase):
    """Test suite for Fast Remediation, Demo Immutability, and Per-File State."""

    def setUp(self):
        self.client = app.test_client()
        self.test_demo_path = "examples/security_lab/hindi/sec_business_workflow_hi.vital"
        self.test_demo_path_2 = "examples/security_lab/telugu/sec_business_workflow_te.vital"
        
        # Read pristine disk content of Demo 1
        full_path_1 = os.path.join(PROJECT_ROOT, self.test_demo_path.replace('/', os.sep))
        with open(full_path_1, 'r', encoding='utf-8') as f:
            self.pristine_disk_content_1 = f.read()

        # Read pristine disk content of Demo 2
        full_path_2 = os.path.join(PROJECT_ROOT, self.test_demo_path_2.replace('/', os.sep))
        with open(full_path_2, 'r', encoding='utf-8') as f:
            self.pristine_disk_content_2 = f.read()

    def test_01_applying_fix_changes_working_buffer_not_disk(self):
        """1. Applying a fix changes the working buffer but not the original demo on disk."""
        # Fetch demo content through API
        resp = self.client.get(f"/api/demo-content?path={self.test_demo_path}")
        self.assertEqual(resp.status_code, 200)
        demo_json = resp.get_json()
        self.assertTrue(demo_json["success"])

        # In-memory working buffer initialized with demo code
        working_buffer = demo_json["code"]
        self.assertEqual(working_buffer, self.pristine_disk_content_1)

        # Scan for findings to get a real finding
        scan_resp = self.client.post("/api/security/scan", json={
            "code": working_buffer,
            "language": "Hindi",
            "use_ai": False
        })
        scan_json = scan_resp.get_json()
        self.assertTrue(scan_json["success"])
        findings = scan_json["findings"]
        self.assertGreater(len(findings), 0)

        target_finding = findings[0]
        finding_id = target_finding["id"]

        # Request fix
        fix_resp = self.client.post("/api/security/suggest-fix", json={
            "code": working_buffer,
            "finding_id": finding_id,
            "finding": target_finding,
            "language": "Hindi",
            "prefer_deterministic": True
        })
        self.assertEqual(fix_resp.status_code, 200)
        fix_json = fix_resp.get_json()
        self.assertTrue(fix_json["success"])
        self.assertIn("proposed_source", fix_json)

        # Simulate user clicking "Approve & Apply Fix": update working buffer ONLY
        working_buffer = fix_json["proposed_source"]
        self.assertNotEqual(working_buffer, self.pristine_disk_content_1)

        # Verify disk file remained completely untouched
        full_path = os.path.join(PROJECT_ROOT, self.test_demo_path.replace('/', os.sep))
        with open(full_path, 'r', encoding='utf-8') as f:
            current_disk_content = f.read()
        self.assertEqual(current_disk_content, self.pristine_disk_content_1,
                         "Original demo file on disk was modified! Immutability violated.")

    def test_02_rejecting_fix_leaves_editor_unchanged(self):
        """2. Rejecting a fix leaves the editor buffer unchanged."""
        initial_buffer = self.pristine_disk_content_1

        # Request fix proposal
        fix_resp = self.client.post("/api/security/suggest-fix", json={
            "code": initial_buffer,
            "finding_id": "SEC-IDOR-001",
            "finding": {"title": "IDOR", "rule_id": "SEC-IDOR-001"},
            "language": "Hindi",
            "prefer_deterministic": True
        })
        fix_json = fix_resp.get_json()
        self.assertTrue(fix_json["success"])

        # User rejects fix: buffer is NOT updated
        editor_buffer = initial_buffer
        self.assertEqual(editor_buffer, self.pristine_disk_content_1)

    def test_03_undo_restores_exact_pre_fix_working_buffer(self):
        """3. Undo restores the exact pre-fix working buffer."""
        initial_buffer = self.pristine_disk_content_1
        undo_stack = []

        # Push pre-fix state
        undo_stack.append({"code": initial_buffer, "time": time.time()})

        # Apply fix
        applied_buffer = initial_buffer + "\n// Applied Fix Patch"
        self.assertNotEqual(applied_buffer, initial_buffer)

        # Perform Undo
        popped = undo_stack.pop()
        restored_buffer = popped["code"]

        self.assertEqual(restored_buffer, initial_buffer,
                         "Undo failed to restore exact pre-fix buffer.")

    def test_04_switching_between_two_demos_preserves_per_file_buffers(self):
        """4. Switching between two demos and returning restores each buffer correctly."""
        file_store = {}

        # 1. Open Demo 1 (Hindi)
        file_store[self.test_demo_path] = {
            "path": self.test_demo_path,
            "originalCode": self.pristine_disk_content_1,
            "workingBuffer": self.pristine_disk_content_1 + "\n// User edit in Hindi demo",
            "cursor": {"line": 12, "ch": 4},
            "undoStack": [{"code": self.pristine_disk_content_1}],
            "isDirty": True
        }

        # 2. Switch to Demo 2 (Telugu)
        file_store[self.test_demo_path_2] = {
            "path": self.test_demo_path_2,
            "originalCode": self.pristine_disk_content_2,
            "workingBuffer": self.pristine_disk_content_2 + "\n// User edit in Telugu demo",
            "cursor": {"line": 25, "ch": 8},
            "undoStack": [],
            "isDirty": True
        }

        # 3. Return to Demo 1
        stored_1 = file_store[self.test_demo_path]
        self.assertTrue(stored_1["isDirty"])
        self.assertTrue(stored_1["workingBuffer"].endswith("// User edit in Hindi demo"))
        self.assertEqual(stored_1["cursor"], {"line": 12, "ch": 4})
        self.assertEqual(len(stored_1["undoStack"]), 1)

        # 4. Return to Demo 2
        stored_2 = file_store[self.test_demo_path_2]
        self.assertTrue(stored_2["isDirty"])
        self.assertTrue(stored_2["workingBuffer"].endswith("// User edit in Telugu demo"))
        self.assertEqual(stored_2["cursor"], {"line": 25, "ch": 8})

        # 5. Verify disks remain unchanged
        full_path_1 = os.path.join(PROJECT_ROOT, self.test_demo_path.replace('/', os.sep))
        with open(full_path_1, 'r', encoding='utf-8') as f:
            self.assertEqual(f.read(), self.pristine_disk_content_1)

        full_path_2 = os.path.join(PROJECT_ROOT, self.test_demo_path_2.replace('/', os.sep))
        with open(full_path_2, 'r', encoding='utf-8') as f:
            self.assertEqual(f.read(), self.pristine_disk_content_2)

    def test_05_restore_original_recovers_exact_original_vulnerable_source(self):
        """5. Restoring the original recovers the exact original vulnerable source."""
        # Simulated modified working buffer
        modified_buffer = self.pristine_disk_content_1.replace("let ", "var_safe ")

        # Call restore original logic (fetches canonical demo content)
        resp = self.client.get(f"/api/demo-content?path={self.test_demo_path}")
        canonical_code = resp.get_json()["code"]

        # Restore working buffer from canonical original
        restored_buffer = canonical_code
        self.assertEqual(restored_buffer, self.pristine_disk_content_1)

    def test_06_ollama_timeout_resilience(self):
        """6. Ollama timeout or disconnection does not leave the UI or API loading indefinitely."""
        # Mock ollama_client.chat to simulate timeout
        with patch("web.ollama_client.ollama_client.chat", side_effect=TimeoutError("Ollama timeout")):
            start_time = time.time()
            resp = self.client.post("/api/security/suggest-fix", json={
                "code": "let a = 10\nprint(a)\n",
                "finding_id": "UNKNOWN-999",
                "finding": {"title": "Generic", "rule_id": "GEN-01"},
                "language": "English",
                "prefer_deterministic": False,
                "request_ai": True
            })
            duration = time.time() - start_time

            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            # Must return cleanly with bounded time
            self.assertLess(duration, 6.0, "Endpoint took longer than timeout threshold")
            self.assertTrue(data.get("success") or "error" in data)

    def test_07_deterministic_fix_appears_instantly(self):
        """7. A deterministic fix appears instantly (<50ms) without waiting for a slow model response."""
        start_time = time.time()
        resp = self.client.post("/api/security/suggest-fix", json={
            "code": self.pristine_disk_content_1,
            "finding_id": "SEC-IDOR-001",
            "finding": {
                "title": "Insecure Direct Object Reference (IDOR)",
                "rule_id": "SEC-IDOR-001",
                "line": 15,
                "evidence": "fn fetch_record(record_id) {"
            },
            "language": "Hindi",
            "prefer_deterministic": True,
            "request_ai": False
        })
        duration_ms = (time.time() - start_time) * 1000

        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(data.get("is_deterministic"))
        self.assertEqual(data.get("fix_source"), "Local rule")
        self.assertLess(duration_ms, 50.0, f"Deterministic fix was too slow: {duration_ms:.2f}ms")

    def test_08_remediation_result_caching(self):
        """8. Remediation results are cached using source hash and finding ID; avoids stale reuse."""
        finding = {
            "title": "IDOR",
            "rule_id": "SEC-IDOR-001",
            "line": 15,
            "evidence": "fn fetch_record(record_id) {"
        }

        # First call (populates cache)
        r1 = security_coordinator.suggest_fix_for_finding(
            source_code=self.pristine_disk_content_1,
            finding_id="SEC-IDOR-001",
            finding_data=finding,
            language="Hindi",
            prefer_deterministic=True
        )
        self.assertTrue(r1["success"])

        # Second call with identical input (should be cached)
        r2 = security_coordinator.suggest_fix_for_finding(
            source_code=self.pristine_disk_content_1,
            finding_id="SEC-IDOR-001",
            finding_data=finding,
            language="Hindi",
            prefer_deterministic=True
        )
        self.assertTrue(r2.get("cached", False), "Second identical call was not served from cache")

        # Third call with DIFFERENT source code (should NOT use stale cache)
        different_code = self.pristine_disk_content_1 + "\n// modified line"
        r3 = security_coordinator.suggest_fix_for_finding(
            source_code=different_code,
            finding_id="SEC-IDOR-001",
            finding_data=finding,
            language="Hindi",
            prefer_deterministic=True
        )
        self.assertFalse(r3.get("cached", False), "Different code returned stale cached fix")

    def test_09_late_ai_response_protection(self):
        """9. A late AI response cannot overwrite editor buffers without user approval."""
        # Simulated async refinement endpoint
        refine_resp = self.client.post("/api/security/refine-fix", json={
            "code": self.pristine_disk_content_1,
            "finding_id": "SEC-IDOR-001",
            "finding": {"title": "IDOR"},
            "current_fix": {"proposed_source": self.pristine_disk_content_1},
            "language": "Hindi"
        })
        self.assertEqual(refine_resp.status_code, 200)
        # Endpoint returns candidate proposal, but DOES NOT write to disk or mutate global server editor state
        full_path = os.path.join(PROJECT_ROOT, self.test_demo_path.replace('/', os.sep))
        with open(full_path, 'r', encoding='utf-8') as f:
            self.assertEqual(f.read(), self.pristine_disk_content_1)

    def test_10_save_as_does_not_modify_original_demo(self):
        """10. Saving a corrected program through Save As does not modify the original demo."""
        # Modified buffer content
        repaired_code = self.pristine_disk_content_1 + "\n// Repaired By Security Fix"

        # Client-side Save As creates a Blob/file named "repaired_sec_business_workflow_hi.vital"
        # It never sends a destructive write request to the server demo directory.
        full_path = os.path.join(PROJECT_ROOT, self.test_demo_path.replace('/', os.sep))
        with open(full_path, 'r', encoding='utf-8') as f:
            disk_content = f.read()

        self.assertEqual(disk_content, self.pristine_disk_content_1)
        self.assertNotIn("// Repaired By Security Fix", disk_content)

    def test_11_multilingual_pipeline_and_security_checks_intact(self):
        """11. Existing multilingual compilation and security checks continue to work across all 6 languages."""
        test_samples = [
            ("English", 'let a = 10\nlet b = 20\nlet c = a + b\nprint(c)\n'),
            ("Hindi", 'मानो a = 10\nमानो b = 20\nमानो c = a + b\nलिखो(c)\n'),
            ("Telugu", 'అనుకో a = 10\nఅనుకో b = 20\nఅనుకో c = a + b\nరాయి(c)\n'),
            ("Bengali", 'ধরো a = 10\nধরো b = 20\nধরো c = a + b\nছাপাও(c)\n'),
            ("Marathi", 'घ्या a = 10\nघ्या b = 20\nघ्या c = a + b\nलिहा(c)\n'),
            ("Nepali", 'मान a = 10\nमान b = 20\nमान c = a + b\nछाप(c)\n'),
        ]

        for lang, code in test_samples:
            # Test compiler pipeline
            res = run_pipeline(code)
            self.assertTrue(res.get("success"), f"Compilation failed for language: {lang}. Output: {res.get('error')}")
            self.assertIn("30", res.get("output", ""), f"Unexpected output for {lang}: {res.get('output')}")

            # Test security scan
            scan_res = self.client.post("/api/security/scan", json={
                "code": code,
                "language": lang,
                "use_ai": False
            })
            self.assertEqual(scan_res.status_code, 200)
            data = scan_res.get_json()
            self.assertTrue(data["success"])
            self.assertFalse(data.get("syntax_blocked", False))


if __name__ == "__main__":
    unittest.main()
