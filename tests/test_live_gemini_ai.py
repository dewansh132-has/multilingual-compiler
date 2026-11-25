# -*- coding: utf-8 -*-
import unittest
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from web.gemini_client import ai_client
from web.ai_remediation_engine import AIRemediationEngine, StageValidator


class TestLiveGeminiAI(unittest.TestCase):

    @unittest.skipIf(
        not (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")) or os.environ.get("VITAL_AI_DISABLED") == "1",
        "Live Gemini test skipped unless GEMINI_API_KEY/GOOGLE_API_KEY is configured and VITAL_AI_DISABLED!=1"
    )
    def test_live_gemini_health_and_remediation(self):
        """Verify Google Gemini model health and real AI remediation."""
        is_healthy, msg, details = ai_client.check_health(force_refresh=True)
        self.assertTrue(is_healthy, f"Gemini API is offline or key invalid: {msg}")
        self.assertIn("gemini", ai_client.model_name.lower())

        code = "let x = 10\nlet sum = x + y\nprint(sum)\n"
        diag = {
            "id": "SEM-LIVE-001",
            "stage_id": "semantic_analysis",
            "stage": "Semantic Analysis",
            "title": "Identifier 'y' referenced before assignment",
            "line": 2,
            "column": 15,
            "code_excerpt": "let sum = x + y",
            "evidence": "y",
            "rule_id": "SEM-UNDECLARED-VAR"
        }

        res = AIRemediationEngine.generate_fix(
            source_code=code,
            stage_id="semantic_analysis",
            finding_id="SEM-LIVE-001",
            finding_data=diag,
            language="English",
            use_ai=True
        )

        self.assertTrue(res.get("success"), f"Gemini remediation failed: {res.get('error')}")
        self.assertIn("proposed_source", res)
        self.assertIn("y", res["proposed_source"])

        # Validate proposed source with compiler
        val = StageValidator.validate_stage("semantic_analysis", res["proposed_source"], "English")
        self.assertTrue(val.passed, f"Proposed source failed validation: {val.error}")


if __name__ == "__main__":
    unittest.main()

