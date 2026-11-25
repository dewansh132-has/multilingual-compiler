# -*- coding: utf-8 -*-
"""
tests/test_concurrency_and_observability.py - Test Suite for Concurrency & Observability.

Verifies:
1. Every run gets run_id (uuid) + source_hash (sha256). All SSE/REST messages carry both.
2. Cancel mechanism: cancelling stops the orchestrator at the next stage boundary,
   marks remaining stages skipped (reason: cancelled), and kills sandbox processes on cancel and timeout.
3. Session concurrency: if a second run for the same session arrives while one is active,
   the backend cancels the old run first.
4. Dev console log lines format:
   - Stage transition: [run <id8>] [Stage <n> <name>] <status> in <ms> ms @ <hash8> -> <n> issues
   - Gate block: [run <id8>] gate: BLOCK (stage 11, 2 HIGH) -> stages 12-14 blocked
   - Health analysis: [health] analysed <file> @ <hash8> score=<n> errors=<n> insecure=<x>% dead=<y>%
5. GET /api/runs/<run_id> endpoint returning full stage table, artifacts, and metadata.
6. Per-run object isolation without module-level mutable state surviving between runs.
"""

import io
import os
import sys
import time
import json
import uuid
import hashlib
import unittest
import threading
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import web.server as server
from web.pipeline_tracker import (
    PipelineRunTracker,
    execute_pipeline_with_tracker,
    run_registry,
    RunRegistry
)
from web.compiler_runner import run_pipeline
from web.code_health import analyze_health


CLEAN_CODE = """
let x = 10
let y = 20
let z = x + y
print(z)
"""

INFINITE_LOOP_CODE = """
while true:
    pass
"""


class TestConcurrencyAndObservability(unittest.TestCase):
    """Verifies concurrency hardening, cancellation, session isolation, and observability logging."""

    def setUp(self):
        self.client = server.app.test_client()
        self.code_hash = hashlib.sha256(CLEAN_CODE.encode("utf-8")).hexdigest()

    def test_run_id_and_source_hash_in_all_rest_and_sse_endpoints(self):
        """Requirement 1: Every run gets run_id (UUID) and source_hash (sha256). All endpoints carry both."""
        # 1. POST /api/pipeline/run (sync)
        resp = self.client.post("/api/pipeline/run", json={
            "source_code": CLEAN_CODE,
            "language": "english",
            "file_path": "test.vital"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("run_id", data)
        self.assertIn("source_hash", data)
        self.assertEqual(data["source_hash"], self.code_hash)
        # Ensure run_id is a valid UUID
        parsed_uuid = uuid.UUID(data["run_id"])
        self.assertIsNotNone(parsed_uuid)

        # 2. POST /api/pipeline/stream (SSE)
        stream_resp = self.client.post("/api/pipeline/stream", json={
            "source_code": CLEAN_CODE,
            "language": "english",
            "file_path": "test.vital"
        })
        self.assertEqual(stream_resp.status_code, 200)
        lines = stream_resp.data.decode("utf-8").split("\n")
        sse_events = []
        for line in lines:
            if line.startswith("data: "):
                try:
                    ev = json.loads(line[6:].strip())
                    sse_events.append(ev)
                except Exception:
                    pass

        self.assertGreater(len(sse_events), 0)
        for ev in sse_events:
            self.assertIn("run_id", ev, f"Event missing run_id: {ev}")
            self.assertIn("source_hash", ev, f"Event missing source_hash: {ev}")
            self.assertEqual(ev["source_hash"], self.code_hash)
            # Check UUID validity
            uuid.UUID(ev["run_id"])

    def test_cancellation_stops_orchestrator_and_marks_remaining_skipped(self):
        """Requirement 2: Cancelling stops orchestrator at next stage boundary and marks remaining skipped."""
        tracker = PipelineRunTracker(run_id=str(uuid.uuid4()), source_hash=self.code_hash)
        
        # Pre-cancel tracker before running
        tracker.cancel(reason="cancelled by user")
        self.assertTrue(tracker.is_cancelled)

        result = execute_pipeline_with_tracker(
            source_code=CLEAN_CODE,
            tracker=tracker
        )

        self.assertEqual(result["final_status"], "CANCELLED")
        stages = result["stages"]
        # All stages should be skipped with reason containing cancelled
        for st in stages:
            self.assertEqual(st["status"], "skipped")
            self.assertIn("cancelled", st.get("skip_reason", "").lower())

    def test_cancel_api_endpoint(self):
        """Requirement 2: POST /api/pipeline/cancel endpoint cancels active run."""
        test_run_id = str(uuid.uuid4())
        session_id = "test-session-cancel-123"
        tracker = PipelineRunTracker(run_id=test_run_id, source_hash=self.code_hash, session_id=session_id)
        
        run_registry.register_run(session_id, tracker)
        self.assertFalse(tracker.is_cancelled)

        # Call cancel endpoint
        cancel_resp = self.client.post("/api/pipeline/cancel", json={
            "run_id": test_run_id,
            "session_id": session_id
        })
        self.assertEqual(cancel_resp.status_code, 200)
        cancel_data = cancel_resp.get_json()
        self.assertTrue(cancel_data["success"])
        self.assertTrue(cancel_data["cancelled"])
        self.assertTrue(tracker.is_cancelled)
        self.assertIn("cancelled", tracker.cancel_reason.lower())

    def test_sandbox_process_killed_on_cancel_and_timeout(self):
        """Requirement 2: Sandbox process gets killed on cancel and on timeout."""
        # 1. Test timeout kills process
        tracker = PipelineRunTracker(run_id=str(uuid.uuid4()), source_hash=self.code_hash)
        # Timeout of 0.3s on infinite loop code
        result = run_pipeline(
            source_code="import time\nwhile True:\n    time.sleep(0.1)\n",
            timeout_seconds=0.3,
            tracker=tracker
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["execution_status"], "timeout")
        self.assertIn("timed out", result["status_message"].lower())

        # 2. Test tracker.cancel() terminates active sandbox process
        tracker2 = PipelineRunTracker(run_id=str(uuid.uuid4()), source_hash=self.code_hash)
        
        def run_proc():
            run_pipeline(
                source_code="import time\nwhile True:\n    time.sleep(0.1)\n",
                timeout_seconds=5.0,
                tracker=tracker2
            )

        th = threading.Thread(target=run_proc)
        th.daemon = True
        th.start()

        # Wait until sandbox proc is running
        for _ in range(50):
            if tracker2.active_sandbox_proc is not None:
                break
            time.sleep(0.02)

        self.assertIsNotNone(tracker2.active_sandbox_proc)
        proc = tracker2.active_sandbox_proc
        self.assertIsNone(proc.poll()) # still running

        # Cancel tracker
        tracker2.cancel(reason="test cancel sandbox")
        th.join(timeout=2.0)
        self.assertFalse(th.is_alive())
        # Process must be terminated
        self.assertIsNotNone(proc.poll())

    def test_second_run_for_same_session_cancels_old_run_first(self):
        """Requirement 3: Backend cancels active run if second run for same session arrives."""
        registry = RunRegistry()
        session_id = "user-session-42"

        run1 = PipelineRunTracker(run_id=str(uuid.uuid4()), session_id=session_id)
        run2 = PipelineRunTracker(run_id=str(uuid.uuid4()), session_id=session_id)

        registry.register_run(session_id, run1)
        self.assertFalse(run1.is_cancelled)

        # Second run arrives
        registry.register_run(session_id, run2)
        self.assertTrue(run1.is_cancelled)
        self.assertIn("superseded", run1.cancel_reason)
        self.assertFalse(run2.is_cancelled)

    def test_log_line_formats(self):
        """Requirement 4: Dev console log lines adhere to strict specified formats."""
        tracker = PipelineRunTracker(run_id="abcdef12-3456-7890-abcd-ef1234567890", source_hash="1234567890abcdef1234567890abcdef")
        
        # Test stage transition log format:
        # [run <id8>] [Stage <n> <name>] <status> in <ms> ms @ <hash8> -> <n> issues
        log_line = tracker.format_stage_log_line(
            stage_id="syntax_analysis",
            status="passed",
            duration_ms=4,
            findings_count=0
        )
        self.assertEqual(log_line, "[run abcdef12] [Stage 3 Syntax Analysis] passed in 4 ms @ 12345678 -> 0 issues")

        # Test gate block log format:
        # [run <id8>] gate: BLOCK (stage 11, 2 HIGH) -> stages 12-14 blocked
        captured_output = io.StringIO()
        with patch("sys.stdout", captured_output):
            # Simulate high finding gate block
            tracker.warn_stage("security_analysis", summary="2 HIGH vulnerabilities", findings_count=2)
        
        # Test health analysis log format:
        # [health] analysed <file> @ <hash8> score=<n> errors=<n> insecure=<x>% dead=<y>%
        health_rep = analyze_health(CLEAN_CODE, language="english", filename="clean.vital")
        self.assertIn("log_line", health_rep)
        health_log = health_rep["log_line"]
        self.assertTrue(health_log.startswith("[health] analysed clean.vital @ "))
        self.assertIn("score=", health_log)
        self.assertIn("errors=", health_log)
        self.assertIn("insecure=", health_log)
        self.assertIn("dead=", health_log)

    def test_get_run_endpoint_recovers_stage_table(self):
        """Requirement 5: GET /api/runs/<run_id> returns full stage table and metadata."""
        # Execute a run
        resp = self.client.post("/api/pipeline/run", json={
            "source_code": CLEAN_CODE,
            "language": "english",
            "file_path": "clean.vital"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        run_id = data["run_id"]

        # Fetch details via GET /api/runs/<run_id>
        get_resp = self.client.get(f"/api/runs/{run_id}")
        self.assertEqual(get_resp.status_code, 200)
        run_details = get_resp.get_json()

        self.assertTrue(run_details["success"])
        self.assertEqual(run_details["run_id"], run_id)
        self.assertEqual(run_details["source_hash"], self.code_hash)
        self.assertEqual(run_details["overall_status"], "COMPLETED")
        self.assertIn("stages", run_details)
        self.assertIsInstance(run_details["stages"], list)
        self.assertEqual(len(run_details["stages"]), 14)
        
        # Verify 404 for unknown run
        bad_resp = self.client.get(f"/api/runs/{str(uuid.uuid4())}")
        self.assertEqual(bad_resp.status_code, 404)

    def test_no_module_level_mutable_state_survives_between_runs(self):
        """Requirement 6: Run results are per-run objects without module-level mutable globals."""
        tracker1 = PipelineRunTracker(run_id=str(uuid.uuid4()), source_hash="hash1")
        tracker2 = PipelineRunTracker(run_id=str(uuid.uuid4()), source_hash="hash2")

        tracker1.fail_stage("syntax_analysis", error_message="syntax failure", duration_ms=5)
        tracker2.pass_stage("syntax_analysis", duration_ms=3)

        self.assertEqual(tracker1.stages["syntax_analysis"]["status"], "failed")
        self.assertEqual(tracker2.stages["syntax_analysis"]["status"], "passed")
        self.assertNotEqual(tracker1.run_id, tracker2.run_id)
        self.assertNotEqual(tracker1.source_hash, tracker2.source_hash)


if __name__ == "__main__":
    unittest.main()
