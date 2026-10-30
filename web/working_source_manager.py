# -*- coding: utf-8 -*-
"""
web/working_source_manager.py — Persistent Single Source-of-Truth Manager for VITAL Working Copies

Guarantees:
  1. Educational demo fixtures (examples/, src/) are pristine and NEVER overwritten.
  2. All working code modifications (manual or AI-generated) are persisted to disk
     in `examples/saved/working_copies/` with full revision tracking and SHA-256 hashing.
  3. Supports undo history stack per file across browser refreshes and server reboots.
  4. Supports instant "Restore Original" to discard working copy and reload the pristine disk fixture.
  5. Synchronizes:
       - Editor buffer
       - Frontend working source
       - Backend working source
       - Persisted working source on disk
       - Compiler input
       - Ollama remediation input
       - Applied AI patches
"""

import os
import sys
import json
import time
import hashlib
from typing import Dict, Any, List, Optional, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKING_STORE_DIR = os.path.join(PROJECT_ROOT, "examples", "saved", "working_copies")
MAX_UNDO_HISTORY = 50


def _normalize_rel_path(rel_path: str) -> str:
    """Normalizes relative path and prevents directory traversal."""
    if not rel_path:
        return ""
    norm = os.path.normpath(rel_path).replace("\\", "/").lstrip("/")
    if ".." in norm:
        raise ValueError("Directory traversal sequence detected in file path.")
    return norm


def _get_storage_paths(rel_path: str) -> Tuple[str, str]:
    """Returns (working_code_file_path, metadata_json_file_path) inside WORKING_STORE_DIR."""
    norm = _normalize_rel_path(rel_path)
    target_code_path = os.path.join(WORKING_STORE_DIR, norm)
    meta_path = target_code_path + ".meta.json"
    return target_code_path, meta_path


def _compute_hash(content: str) -> str:
    """Computes SHA-256 hex digest for code content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class WorkingSourceManager:
    """Central controller for working source persistence, revisions, and recovery."""

    def __init__(self, storage_dir: str = WORKING_STORE_DIR):
        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)

    def get_original_source(self, rel_path: str) -> Tuple[bool, str, str]:
        """
        Reads the pristine disk fixture from PROJECT_ROOT.
        Returns: (success: bool, content: str, error_message: str)
        """
        try:
            norm = _normalize_rel_path(rel_path)
            full_path = os.path.abspath(os.path.join(PROJECT_ROOT, norm))
            common = os.path.commonpath([full_path, PROJECT_ROOT])
            if common != PROJECT_ROOT or not os.path.isfile(full_path):
                return False, "", f"Original file not found: {rel_path}"

            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            return True, content, ""
        except Exception as e:
            return False, "", str(e)

    def get_working_source(self, rel_path: str) -> Dict[str, Any]:
        """
        Retrieves the active working source. If a persisted working copy exists,
        returns it; otherwise falls back to the pristine original file.
        """
        norm = _normalize_rel_path(rel_path)
        ok, original_code, err = self.get_original_source(norm)
        if not ok:
            return {
                "success": False,
                "error": err,
                "file_path": norm
            }

        code_path, meta_path = _get_storage_paths(norm)

        # Check if working copy exists
        if os.path.exists(code_path) and os.path.isfile(code_path):
            try:
                with open(code_path, "r", encoding="utf-8", errors="replace") as f:
                    working_code = f.read()

                meta = {}
                if os.path.exists(meta_path):
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)

                content_hash = _compute_hash(working_code)
                orig_hash = _compute_hash(original_code)

                return {
                    "success": True,
                    "file_path": norm,
                    "code": working_code,
                    "working_code": working_code,
                    "working_source": working_code,
                    "original_code": original_code,
                    "original_source": original_code,
                    "source_revision": meta.get("source_revision", 1),
                    "content_hash": content_hash,
                    "is_dirty": (content_hash != orig_hash),
                    "is_modified": (content_hash != orig_hash),
                    "has_working_copy": True,
                    "last_saved": meta.get("last_saved", os.path.getmtime(code_path)),
                    "undo_count": len(meta.get("undo_stack", [])),
                    "can_undo": len(meta.get("undo_stack", [])) > 0
                }
            except Exception as e:
                # If reading working copy fails, gracefully fallback to original
                pass

        # No working copy yet — pristine original is the source of truth
        orig_hash = _compute_hash(original_code)
        return {
            "success": True,
            "file_path": norm,
            "code": original_code,
            "working_code": original_code,
            "working_source": original_code,
            "original_code": original_code,
            "original_source": original_code,
            "source_revision": 1,
            "content_hash": orig_hash,
            "is_dirty": False,
            "is_modified": False,
            "has_working_copy": False,
            "last_saved": None,
            "undo_count": 0,
            "can_undo": False
        }

    def save_working_source(
        self,
        rel_path: str,
        code: str,
        expected_revision: Optional[int] = None,
        label: str = ""
    ) -> Dict[str, Any]:
        """
        Persists a modified working source safely to disk in WORKING_STORE_DIR.
        Pushes the previous version to undo history.
        Original files in examples/ and src/ are untouched.
        """
        try:
            norm = _normalize_rel_path(rel_path)
            if not norm:
                return {"success": False, "error": "Empty file path"}

            ok, original_code, err = self.get_original_source(norm)
            if not ok:
                return {"success": False, "error": err}

            code_path, meta_path = _get_storage_paths(norm)
            os.makedirs(os.path.dirname(code_path), exist_ok=True)

            current_working = None
            meta = {
                "file_path": norm,
                "source_revision": 1,
                "undo_stack": []
            }

            if os.path.exists(code_path):
                with open(code_path, "r", encoding="utf-8", errors="replace") as f:
                    current_working = f.read()

            if os.path.exists(meta_path):
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                except Exception:
                    pass

            prev_code = current_working if current_working is not None else original_code
            prev_rev = meta.get("source_revision", 1)

            # Snapshot previous code to undo stack if code is changing
            if prev_code != code:
                undo_entry = {
                    "code": prev_code,
                    "source_revision": prev_rev,
                    "timestamp": time.time(),
                    "label": label or f"Revision {prev_rev} snapshot",
                    "content_hash": _compute_hash(prev_code)
                }
                undo_stack = meta.get("undo_stack", [])
                undo_stack.append(undo_entry)
                if len(undo_stack) > MAX_UNDO_HISTORY:
                    undo_stack = undo_stack[-MAX_UNDO_HISTORY:]
                meta["undo_stack"] = undo_stack
                new_rev = prev_rev + 1
            else:
                new_rev = prev_rev

            new_hash = _compute_hash(code)
            orig_hash = _compute_hash(original_code)
            now = time.time()

            meta["source_revision"] = new_rev
            meta["content_hash"] = new_hash
            meta["last_saved"] = now
            meta["is_dirty"] = (new_hash != orig_hash)

            # Atomic file write: write to temp and rename
            temp_code_path = code_path + ".tmp"
            with open(temp_code_path, "w", encoding="utf-8") as f:
                f.write(code)
            if os.path.exists(code_path):
                os.replace(temp_code_path, code_path)
            else:
                os.rename(temp_code_path, code_path)

            temp_meta_path = meta_path + ".tmp"
            with open(temp_meta_path, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2, ensure_ascii=False)
            if os.path.exists(meta_path):
                os.replace(temp_meta_path, meta_path)
            else:
                os.rename(temp_meta_path, meta_path)

            return {
                "success": True,
                "file_path": norm,
                "code": code,
                "working_code": code,
                "working_source": code,
                "source_revision": new_rev,
                "content_hash": new_hash,
                "is_dirty": (new_hash != orig_hash),
                "is_modified": (new_hash != orig_hash),
                "saved_at": now,
                "undo_count": len(meta.get("undo_stack", [])),
                "can_undo": len(meta.get("undo_stack", [])) > 0,
                "message": f"Working copy for {os.path.basename(norm)} persisted at Revision {new_rev}."
            }
        except Exception as e:
            return {"success": False, "error": f"Failed to persist working source: {e}"}

    def undo_working_source(self, rel_path: str) -> Dict[str, Any]:
        """
        Reverts the working source to the previous snapshot on the undo stack.
        """
        try:
            norm = _normalize_rel_path(rel_path)
            code_path, meta_path = _get_storage_paths(norm)

            if not os.path.exists(meta_path):
                return {"success": False, "error": "No undo history available for this file."}

            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)

            undo_stack = meta.get("undo_stack", [])
            if not undo_stack:
                return {"success": False, "error": "Undo history is empty."}

            last_snapshot = undo_stack.pop()
            restored_code = last_snapshot["code"]
            restored_rev = meta.get("source_revision", 1) + 1
            restored_hash = _compute_hash(restored_code)
            now = time.time()

            ok, original_code, _ = self.get_original_source(norm)
            orig_hash = _compute_hash(original_code) if ok else ""

            meta["source_revision"] = restored_rev
            meta["content_hash"] = restored_hash
            meta["last_saved"] = now
            meta["is_dirty"] = (restored_hash != orig_hash)
            meta["undo_stack"] = undo_stack

            with open(code_path, "w", encoding="utf-8") as f:
                f.write(restored_code)

            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2, ensure_ascii=False)

            return {
                "success": True,
                "file_path": norm,
                "code": restored_code,
                "working_code": restored_code,
                "working_source": restored_code,
                "source_revision": restored_rev,
                "content_hash": restored_hash,
                "is_dirty": meta["is_dirty"],
                "is_modified": meta["is_dirty"],
                "undo_count": len(undo_stack),
                "can_undo": len(undo_stack) > 0,
                "label": last_snapshot.get("label", "Undo"),
                "message": f"Reverted working source to snapshot ({last_snapshot.get('label', 'Undo')})."
            }
        except Exception as e:
            return {"success": False, "error": f"Undo operation failed: {e}"}

    def restore_original_source(self, rel_path: str) -> Dict[str, Any]:
        """
        Discards any modified working copy and resets back to the pristine
        original disk fixture.
        """
        try:
            norm = _normalize_rel_path(rel_path)
            ok, original_code, err = self.get_original_source(norm)
            if not ok:
                return {"success": False, "error": err}

            code_path, meta_path = _get_storage_paths(norm)
            if os.path.exists(code_path):
                try:
                    os.remove(code_path)
                except Exception:
                    pass
            if os.path.exists(meta_path):
                try:
                    os.remove(meta_path)
                except Exception:
                    pass

            orig_hash = _compute_hash(original_code)
            return {
                "success": True,
                "file_path": norm,
                "code": original_code,
                "working_code": original_code,
                "working_source": original_code,
                "original_code": original_code,
                "original_source": original_code,
                "source_revision": 1,
                "content_hash": orig_hash,
                "is_dirty": False,
                "is_modified": False,
                "undo_count": 0,
                "can_undo": False,
                "message": f"Restored {os.path.basename(norm)} to pristine original demo fixture."
            }
        except Exception as e:
            return {"success": False, "error": f"Failed to restore original file: {e}"}


# Global singleton
working_source_manager = WorkingSourceManager()

# Class-level delegations for convenient static-style access
WorkingSourceManager.get_working_source = working_source_manager.get_working_source
WorkingSourceManager.get_working_copy = working_source_manager.get_working_source
WorkingSourceManager.save_working_source = working_source_manager.save_working_source
WorkingSourceManager.save_working_copy = working_source_manager.save_working_source
WorkingSourceManager.undo_working_source = working_source_manager.undo_working_source
WorkingSourceManager.undo_working_copy = working_source_manager.undo_working_source
WorkingSourceManager.restore_original_source = working_source_manager.restore_original_source
WorkingSourceManager.restore_original = working_source_manager.restore_original_source
