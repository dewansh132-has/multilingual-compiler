"""Revision, rollback, hash consistency and undo through the editor HTTP contract."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.source_revision import source_hash
from web.server import app


class FixFlowHTTP(unittest.TestCase):
    def setUp(self):
        os.environ["VITAL_AI_DISABLED"] = "1"
        self.assertEqual(os.environ.get("VITAL_AI_DISABLED"), "1")
        self.client = app.test_client()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.enterContext(patch("web.working_source_manager.WORKING_STORE_DIR", self.temp.name))
        self.file = "examples/english/arithmetic.vital"
        self.source = 'let base = 3\nprint(missing_value)\n'
        self.rev = 1

    def post(self, endpoint, **data):
        envelope = dict(source=self.source, language="English", file_id=self.file,
                        revision_id=source_hash(self.source)[:12], source_revision=self.rev)
        return self.client.post("/api/" + endpoint, json={**envelope, **data})

    def test_apply_and_undo(self):
        stages = self.post("pipeline/run", code=self.source, use_ai_security=False, pause_on_error=True).json
        parser = next(s for s in stages["stages"] if s["id"] == "syntax_analysis")
        semantic = next(s for s in stages["stages"] if s["id"] == "semantic_analysis")
        self.assertEqual(parser["status"], "completed")
        self.assertEqual(semantic["status"], "failed")
        result = self.post("ai/fix-all", diagnostics=semantic["details"]["findings"], stage_id=semantic["id"]).json
        self.assertTrue(result["applied_fixes"], result)
        original = self.source
        response = self.post("ai/apply-fix", code=result["proposed_source"],
                             proposed_hash=result["proposed_hash"], preview_revision=result["revision_id"])
        self.assertEqual(response.status_code, 200, response.json)
        self.source = result["proposed_source"]
        self.rev = response.json["source_revision"]
        disk = Path(self.temp.name) / self.file
        self.assertEqual(hashlib.sha256(disk.read_bytes()).hexdigest(), response.json["content_hash"])
        self.assertEqual(disk.read_bytes(), self.source.encode())
        loaded = self.client.get("/api/demo-content", query_string={"path": self.file}).json
        self.assertEqual(loaded["code"], self.source)
        self.assertEqual(loaded["undo_count"], 1)
        after = self.post("pipeline/run", code=self.source, use_ai_security=False, pause_on_error=True).json
        self.assertEqual([s["status"] for s in after["stages"][:10]], ["completed"] * 10)
        again = self.post("ai/fix-all", diagnostics=[], stage_id=semantic["id"]).json
        self.assertEqual(again["proposed_source"], self.source)
        self.assertFalse(again["applied_fixes"])
        undo = self.post("working-source/undo", path=self.file).json
        self.assertEqual(undo["code"].encode(), original.encode())
        self.assertEqual(undo["undo_count"], 0)

    def test_regression_rollback(self):
        self.source = "print(1)\n"
        bad = self.source + "}"
        response = self.post("ai/apply-fix", code=bad, preview_revision=source_hash(self.source)[:12],
                             proposed_hash=source_hash(bad))
        self.assertEqual(response.status_code, 400)
        self.assertTrue(response.json["retained_original"])
        self.assertFalse(list(Path(self.temp.name).rglob("*.vital")))

    def test_stale_stream(self):
        stream = self.post("pipeline/stream", run_id="old", pause_on_error=True, use_ai_security=False)
        event = next(json.loads(line[5:]) for line in stream.get_data(as_text=True).splitlines() if line)
        self.assertEqual(event["revision_id"], source_hash(self.source)[:12])
        self.assertEqual(self.post("pipeline/run", revision_id="obsolete").status_code, 409)
        if shutil.which("node"):
            js = (ROOT / "web/static/js/ide.js").read_text(encoding="utf8")
            handler = js.split("  function handlePipelineEvent(event) {", 1)[1].split("    state.pipeline.hasReceivedEventForRun = true;", 1)[0]
            program = "const state={pipeline:{activeRunId:'new',compiledSource:'edited'},editor:{getValue:()=>'edited'}};" + "function handle(event) {" + handler + "throw Error('stale event accepted')} handle(" + json.dumps(event) + ");"
            subprocess.run(["node", "-e", program], timeout=10, check=True)

    def test_shell_literal_position_and_rescan(self):
        self.source = 'let label = "run diagnostics ; rm temporary"\nprint(label)\n'
        found = self.post("security/scan", code=self.source, use_ai=False).json["findings"]
        shell, = [f for f in found if "SEC-LEX-004" in f["rule_ids"]]
        self.assertEqual((shell["line"], shell["column"]), (1, self.source.index(";")+1))
        result = self.post("security/suggest-fix", code=self.source, finding=shell,
                           finding_id=shell["id"], stage_id="lexical_analysis").json
        self.assertEqual(result["proposed_source"], 'let label = "run diagnostics"\nprint(label)\n')
        self.source = result["proposed_source"]
        self.assertEqual(self.post("security/scan", code=self.source, use_ai=False).json["findings"], [])

    def test_hunk_generation(self):
        """Verify difflib hunk generation for single-line change, added line, and removed line."""
        from web.fix_orchestrator import compute_diff_hunks

        # 1. Single-line change
        before1 = "let a = 1\nlet b = 2\nlet c = 3"
        after1 = "let a = 1\nlet b = 99\nlet c = 3"
        r1 = compute_diff_hunks(before1, after1, n_context=2)
        self.assertEqual(r1["line_start"], 2)
        self.assertEqual(r1["line_end"], 2)
        self.assertEqual(r1["before"], "let b = 2")
        self.assertEqual(r1["after"], "let b = 99")
        self.assertEqual(len(r1["hunks"]), 1)
        hunk1 = r1["hunks"][0]
        self.assertEqual(hunk1["old_start"], 1)
        self.assertEqual(hunk1["new_start"], 1)
        self.assertTrue(any(row["type"] == "delete" and row["text"] == "let b = 2" for row in hunk1["lines"]))
        self.assertTrue(any(row["type"] == "insert" and row["text"] == "let b = 99" for row in hunk1["lines"]))
        self.assertTrue(any(row["type"] == "context" and row["text"] == "let a = 1" for row in hunk1["lines"]))

        # 2. Added line
        before2 = "let a = 1\nlet c = 3"
        after2 = "let a = 1\nlet b = 2\nlet c = 3"
        r2 = compute_diff_hunks(before2, after2, n_context=2)
        self.assertEqual(r2["line_start"], 2)
        self.assertEqual(r2["before"], "")
        self.assertEqual(r2["after"], "let b = 2")
        self.assertEqual(len(r2["hunks"]), 1)
        hunk2 = r2["hunks"][0]
        self.assertTrue(any(row["type"] == "insert" and row["text"] == "let b = 2" for row in hunk2["lines"]))

        # 3. Removed line
        before3 = "let a = 1\nlet b = 2\nlet c = 3"
        after3 = "let a = 1\nlet c = 3"
        r3 = compute_diff_hunks(before3, after3, n_context=2)
        self.assertEqual(r3["line_start"], 2)
        self.assertEqual(r3["line_end"], 2)
        self.assertEqual(r3["before"], "let b = 2")
        self.assertEqual(r3["after"], "")
        self.assertEqual(len(r3["hunks"]), 1)
        hunk3 = r3["hunks"][0]
        self.assertTrue(any(row["type"] == "delete" and row["text"] == "let b = 2" for row in hunk3["lines"]))


if __name__ == "__main__":
    unittest.main()
