import unittest
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from web.ollama_client import ollama_client
from web.ai_remediation_engine import AIRemediationEngine, StageValidator


class TestLiveOllamaAI(unittest.TestCase):

    def test_live_ollama_health_and_remediation(self):
        """Verify local Ollama qwen2.5-coder:7b-instruct model health and remediation."""
        is_healthy, msg, details = ollama_client.check_health(force_refresh=True)
        self.assertTrue(is_healthy, f"Local Ollama is offline: {msg}")
        self.assertEqual(ollama_client.model, "qwen2.5-coder:7b-instruct")

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

        self.assertTrue(res.get("success"), f"Ollama remediation failed: {res.get('error')}")
        self.assertIn("proposed_source", res)
        self.assertIn("y", res["proposed_source"])

        # Validate proposed source with compiler
        val = StageValidator.validate_stage("semantic_analysis", res["proposed_source"], "English")
        self.assertTrue(val.passed, f"Proposed source failed validation: {val.error}")


if __name__ == "__main__":
    unittest.main()

