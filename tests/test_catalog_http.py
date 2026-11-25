"""Catalog HTTP regression. Select a language method to run a bounded chunk."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.audit_http import audit
from web.server import app


class CatalogHTTP(unittest.TestCase):
    def setUp(self):
        os.environ.setdefault("VITAL_AI_DISABLED", "1")
        self.assertEqual(os.environ.get("VITAL_AI_DISABLED"), "1")
        self.client = app.test_client()
        self.stages = [s["id"] for s in self.client.get("/api/pipeline/stages").json["stages"]]
        self.files = self.client.get("/api/demos").json["data"]["demos"]
        self.temp = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch("web.working_source_manager.WORKING_STORE_DIR", self.temp))
        self.enterContext(patch.dict(app.config, AUDIT_SYNC=True))

    def check_language(self, language):
        demos = [f for f in self.files if f["category"] != "My Saved Programs"]
        self.assertGreaterEqual(len(demos), 40)
        for file in (f for f in demos if f["language"] == language):
            with self.subTest(file=file["path"]):
                row = audit(self.client, self.stages, file, Path(self.temp))
                if file["is_security_lab"]:
                    self.assertTrue(row["findings_before"])
                    self.assertTrue(any(row[k] in {"warning", "failed"} for k in self.stages))
                self.assertTrue(all(s in ("completed", "passed") for s in row["mandatory_after"]))
                self.assertEqual(row["reached_14"], "Y")
                self.assertEqual(row["findings_after"], "")
                self.assertEqual(row["rejected"], [])
                self.assertTrue(row["repeat_stable"])
                self.assertLess(row["fix_seconds"], 3)


def test_language(language):
    def check(self):
        self.check_language(language)
    return check


for language in ("English", "Hindi", "Bengali", "Marathi", "Telugu", "Nepali", "Multilingual Fusion"):
    setattr(CatalogHTTP, "test_" + language.lower().replace(" ", "_"), test_language(language))
del test_language

if __name__ == "__main__":
    unittest.main()
