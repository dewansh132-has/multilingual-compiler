import os
import unittest
import hashlib
import json
from web.server import app
from web.working_source_manager import _get_storage_paths, working_source_manager
from web.demo_manager import get_demo_content

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES_DIR = os.path.join(PROJECT_ROOT, "examples")


def hash_all_pristine_examples():
    file_hashes = {}
    for root, _, files in os.walk(PROJECT_ROOT):
        if any(p in root for p in [".git", ".venv", "node_modules", ".gemini", "working_copies", "scratch"]):
            continue
        for f in files:
            if f.endswith(".vital"):
                full_p = os.path.abspath(os.path.join(root, f))
                with open(full_p, "rb") as fh:
                    file_hashes[full_p] = hashlib.sha256(fh.read()).hexdigest()
    return file_hashes


class TestWorkingCopyImmutability(unittest.TestCase):
    """
    Task B: Working copy isolation & demo immutability tests.
    Ensures pristine demo files in examples/ remain strictly byte-identical across all fix flows.
    """

    def setUp(self):
        self.client = app.test_client()
        self.initial_hashes = hash_all_pristine_examples()
        self.assertGreaterEqual(len(self.initial_hashes), 86, "Expected at least 86 pristine demo files.")

    def tearDown(self):
        # Always verify byte-identical state
        current_hashes = hash_all_pristine_examples()
        self.assertEqual(len(self.initial_hashes), len(current_hashes))
        for path, orig_hash in self.initial_hashes.items():
            curr_hash = current_hashes.get(path)
            self.assertEqual(
                curr_hash, orig_hash,
                f"Pristine demo file was mutated: {path}"
            )
        # Clean up working copies
        working_source_manager.clear_all_working_copies()

    def test_01_examples_remain_byte_identical_after_fix_and_save_flow(self):
        """Task B6: Pristine examples/ files remain byte-identical after remediation, saving, and clear-all."""
        rel_path = "examples/english/hello.vital"
        test_file = os.path.join(PROJECT_ROOT, rel_path)
        with open(test_file, "r", encoding="utf-8") as f:
            pristine_code = f.read()

        # Modified code that passes stages 1-10
        valid_modified_code = pristine_code + '\nprint("Safe working copy test.")\n'

        # 1. Persist valid modification to working copy
        save_res = self.client.post("/api/working-source/save", json={
            "path": test_file,
            "code": valid_modified_code,
            "language": "English"
        }).get_json()
        self.assertTrue(save_res.get("success"), f"Save failed: {save_res.get('error')}")

        # 2. Load demo via demo_manager
        loaded = get_demo_content(rel_path)
        self.assertTrue(loaded.get("is_modified"))
        self.assertEqual(loaded.get("code"), valid_modified_code)

        # 3. Clear all working copies via endpoint
        clear_res = self.client.post("/api/working-copy/clear-all").get_json()
        self.assertTrue(clear_res.get("success"))
        self.assertIn("working copy", clear_res.get("message", "").lower())

        # 4. Reload demo: must now be pristine
        reloaded = get_demo_content(rel_path)
        self.assertFalse(reloaded.get("is_modified"))
        self.assertEqual(reloaded.get("code"), pristine_code)

    def test_02_broken_fix_rejected_from_working_copy_persistence(self):
        """Task B1: A fix may be persisted to a working copy ONLY after the patched source passes stages 1-10."""
        test_file = os.path.join(EXAMPLES_DIR, "english", "hello.vital")
        broken_code = "fn main() { let x = 10 + \n"  # Syntax error

        # Attempt to save broken source to working copy
        save_res = working_source_manager.save_working_source(test_file, broken_code, language="English")
        self.assertFalse(save_res.get("success"))
        self.assertIn("Working copy rejected", save_res.get("error", ""))

    def test_03_corrupted_working_copy_automatically_discarded_on_load(self):
        """Task B2: Corrupted working copy failing stages 1-10 is automatically discarded on load."""
        rel_path = "examples/english/hello.vital"
        test_file = os.path.join(PROJECT_ROOT, rel_path)
        with open(test_file, "r", encoding="utf-8") as f:
            pristine_code = f.read()

        # Force-write corrupted code directly into working copy store
        working_file, meta_file = _get_storage_paths(test_file, language="English")
        os.makedirs(os.path.dirname(working_file), exist_ok=True)
        with open(working_file, "w", encoding="utf-8") as f:
            f.write("let broken = (1 + 2\n")  # Unclosed paren
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump({
                "source_revision": 2,
                "pristine_sha256": hashlib.sha256(pristine_code.encode("utf-8")).hexdigest(),
                "history": []
            }, f)

        # Loading demo should detect corruption, discard working copy, and load pristine
        loaded = get_demo_content(rel_path)
        self.assertTrue(loaded.get("corrupted_discarded"))
        self.assertIn("Corrupted working copy discarded", loaded.get("notice", ""))
        self.assertFalse(loaded.get("is_modified"))
        self.assertEqual(loaded.get("code"), pristine_code)
        self.assertFalse(os.path.exists(working_file), "Corrupted working copy file was not deleted!")

    def test_04_pristine_sha256_mismatch_discards_working_copy(self):
        """Task B3: Discards working copy if pristine demo has changed since."""
        rel_path = "examples/english/hello.vital"
        test_file = os.path.join(PROJECT_ROOT, rel_path)
        working_file, meta_file = _get_storage_paths(test_file, language="English")
        os.makedirs(os.path.dirname(working_file), exist_ok=True)
        with open(working_file, "w", encoding="utf-8") as f:
            f.write('print("modified hello")\n')
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump({
                "source_revision": 2,
                "pristine_sha256": "stale_hash_that_does_not_match_pristine_demo",
                "history": []
            }, f)

        loaded = working_source_manager.get_working_source(test_file, language="English")
        self.assertFalse(loaded.get("is_modified"))
        self.assertFalse(os.path.exists(working_file), "Stale working copy file was not discarded!")

    def test_05_unique_keys_per_language_and_relative_path(self):
        """Task B5: Working-copy key is unique per (language, relative path) so two demos cannot collide."""
        p_eng, m_eng = _get_storage_paths("hello.vital", language="English")
        p_hin, m_hin = _get_storage_paths("hello.vital", language="Hindi")
        p_tel, m_tel = _get_storage_paths("hello.vital", language="Telugu")

        self.assertNotEqual(p_eng, p_hin)
        self.assertNotEqual(p_eng, p_tel)
        self.assertNotEqual(p_hin, p_tel)


if __name__ == "__main__":
    unittest.main()
