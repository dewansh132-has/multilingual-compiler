# -*- coding: utf-8 -*-
"""
web/fixflow_logger.py — Temporary Diagnostic Logger for Fix Flow & Cascades

Records diagnostic entries to logs/fixflow.log:
- revision_id before/after
- which stage was targeted
- which model was called
- prompt size
- latency
- the exact patch (unified diff)
- the per-stage status of all 14 stages before and after the patch

This file and its hooks are purely diagnostic and easy to remove.
"""

import os
import time
import difflib
from typing import Dict, Any, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
LOG_FILE = os.path.join(LOGS_DIR, "fixflow.log")

# In-memory registry to correlate fix generation with fix application
_LAST_FIX_METADATA: Dict[str, Any] = {}


def _ensure_log_dir():
    os.makedirs(LOGS_DIR, exist_ok=True)


def format_stage_table(stages: Any) -> str:
    """Formats 14 stages into a clean aligned table."""
    lines = []
    lines.append("  Stage ID               | Status     | Summary")
    lines.append("  -----------------------+------------+----------------------------------------")
    
    stages_list = []
    if isinstance(stages, dict):
        stages_list = list(stages.values())
    elif isinstance(stages, list):
        stages_list = stages

    for st in stages_list:
        if isinstance(st, dict):
            sid = st.get("id", "unknown")
            st_status = str(st.get("status", "unknown")).upper()
            st_summary = str(st.get("summary", ""))[:45]
        else:
            sid = str(st)
            st_status = "UNKNOWN"
            st_summary = ""
        lines.append(f"  {sid:22s} | {st_status:10s} | {st_summary}")
    return "\n".join(lines)


def log_compile_event(
    run_id: str,
    source_revision: int,
    source_hash: str,
    language: str,
    stages: Dict[str, Any],
    final_status: str,
    duration_ms: float
):
    """Logs a compiler pipeline run with per-stage statuses."""
    _ensure_log_dir()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    table = format_stage_table(stages)
    entry = (
        f"================================================================================\n"
        f"[{timestamp}] [COMPILE EVENT] Run ID: {run_id}\n"
        f"Revision: Rev {source_revision} | Hash: {source_hash[:16] if source_hash else 'none'}... | Language: {language}\n"
        f"Duration: {duration_ms:.2f} ms | Overall Status: {final_status.upper()}\n"
        f"14-Stage Breakdown:\n"
        f"{table}\n"
        f"================================================================================\n\n"
    )
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception as e:
        print(f"[FixflowLogger Error]: {e}")


def register_fix_generation(
    file_path: str,
    stage_id: str,
    model_name: str,
    prompt_size_chars: int,
    latency_ms: float,
    patch_diff: str,
    proposed_source: str,
    original_source: str
):
    """Caches fix generation metadata so it can be combined upon patch approval/application."""
    key = file_path or "default"
    _LAST_FIX_METADATA[key] = {
        "stage_id": stage_id,
        "model_name": model_name,
        "prompt_size_chars": prompt_size_chars,
        "latency_ms": latency_ms,
        "patch_diff": patch_diff,
        "proposed_source": proposed_source,
        "original_source": original_source,
        "timestamp": time.time()
    }


def log_fix_event(
    revision_before: int,
    revision_after: int,
    target_stage: str,
    model_name: str,
    prompt_size_chars: int,
    latency_ms: float,
    patch_diff: str,
    stages_before: Dict[str, Any],
    stages_after: Dict[str, Any],
    action: str = "FIX ALL",
    file_path: str = ""
):
    """Logs full patch lifecycle before and after application."""
    _ensure_log_dir()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    table_before = format_stage_table(stages_before)
    table_after = format_stage_table(stages_after)

    entry = (
        f"################################################################################\n"
        f"[{timestamp}] [FIX EVENT: {action}] File: {file_path}\n"
        f"Target Stage:        {target_stage}\n"
        f"Revision Change:     Rev {revision_before} -> Rev {revision_after}\n"
        f"Model Called:        {model_name or 'Deterministic / Fallback'}\n"
        f"Prompt Size:         {prompt_size_chars} chars\n"
        f"Remediation Latency: {latency_ms:.2f} ms\n"
        f"--------------------------------------------------------------------------------\n"
        f"PER-STAGE STATUS BEFORE PATCH (Rev {revision_before}):\n"
        f"{table_before}\n"
        f"--------------------------------------------------------------------------------\n"
        f"EXACT PATCH (UNIFIED DIFF):\n"
        f"{patch_diff.strip() if patch_diff else '[No Diff Generated]'}\n"
        f"--------------------------------------------------------------------------------\n"
        f"PER-STAGE STATUS AFTER PATCH (Rev {revision_after}):\n"
        f"{table_after}\n"
        f"################################################################################\n\n"
    )
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception as e:
        print(f"[FixflowLogger Error]: {e}")
