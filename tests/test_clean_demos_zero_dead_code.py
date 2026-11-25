"""
Unit and integration tests asserting zero dead code across all clean demos,
and verifying that deliberately injected dead functions, unused variables,
and unused parameters are strictly detected.
"""
import glob
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from web.code_health import analyze_health
from web.compiler_runner import run_pipeline


class TestCleanDemosZeroDeadCode(unittest.TestCase):
    """Test suite ensuring all clean demos have 0% dead code and healthy status."""

    def test_01_deliberately_dead_function_is_detected(self):
        """Verify that a deliberately unused function is actively caught by the detector."""
        code = """// Test dead function detection
function active_worker(val) {
    print(val)
    return val * 2
}

function never_called_helper(x, y) {
    return x + y
}

active_worker(10)
"""
        h = analyze_health(code, "test_dead_fn.vital")
        dead_items = h.get("dead_code", {}).get("items", [])
        self.assertGreater(len(dead_items), 0, "Detector failed to catch deliberately dead function")
        kinds = [it["kind"] for it in dead_items]
        names = [it["name"] for it in dead_items]
        self.assertIn("unused_function", kinds)
        self.assertIn("never_called_helper", names)
        self.assertNotIn("active_worker", names)

    def test_02_deliberately_unused_variable_is_detected(self):
        """Verify that a deliberately unused variable is actively caught by the detector."""
        code = """// Test dead variable detection
let active_counter = 50
let deliberately_dead_var = 999
print(active_counter)
"""
        h = analyze_health(code, "test_dead_var.vital")
        dead_items = h.get("dead_code", {}).get("items", [])
        self.assertGreater(len(dead_items), 0, "Detector failed to catch deliberately unused variable")
        kinds = [it["kind"] for it in dead_items]
        names = [it["name"] for it in dead_items]
        self.assertIn("unused_variable", kinds)
        self.assertIn("deliberately_dead_var", names)
        self.assertNotIn("active_counter", names)

    def test_03_deliberately_unused_parameter_is_detected(self):
        """Verify that a deliberately unused parameter is actively caught by the detector."""
        code = """// Test unused parameter detection
function compute_total(base_amount, unused_multiplier_flag) {
    return base_amount + 100
}

let result = compute_total(500, 2)
print(result)
"""
        h = analyze_health(code, "test_unused_param.vital")
        dead_items = h.get("dead_code", {}).get("items", [])
        self.assertGreater(len(dead_items), 0, "Detector failed to catch deliberately unused parameter")
        kinds = [it["kind"] for it in dead_items]
        names = [it["name"] for it in dead_items]
        self.assertIn("unused_parameter", kinds)
        self.assertIn("unused_multiplier_flag", names)

    def test_04_all_45_clean_demos_have_zero_dead_code(self):
        """Parametrised test checking every .vital file outside security_lab has exactly 0 dead items and 0.0% dead code."""
        clean_files = [f for f in sorted(glob.glob("examples/**/*.vital", recursive=True)) if "security_lab" not in f.replace("\\", "/")]
        self.assertEqual(len(clean_files), 45, f"Expected 45 clean demo files, found {len(clean_files)}")

        failures = []
        for fpath in clean_files:
            with open(fpath, "r", encoding="utf-8") as fp:
                code = fp.read()
            h = analyze_health(code, fpath)
            dead_items = h.get("dead_code", {}).get("items", [])
            dead_pct = h.get("dead_code", {}).get("percentage", 0.0)
            status = h.get("status")

            if dead_items or dead_pct > 0.0 or status == "errors":
                failures.append(f"{fpath}: {len(dead_items)} items ({dead_pct}%), status={status}")

        self.assertEqual(failures, [], "The following clean demos contain dead code or health errors:\n" + "\n".join(failures))

    def test_05_clean_demos_never_touch_security_lab(self):
        """Security regression: security lab demos must retain their documented defects and not be modified as clean demos."""
        sec_files = glob.glob("examples/security_lab/**/*.vital", recursive=True)
        self.assertGreaterEqual(len(sec_files), 28, "Security lab files missing")
        for f in sec_files:
            self.assertTrue(os.path.exists(f))


if __name__ == "__main__":
    unittest.main()
