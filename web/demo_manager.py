# -*- coding: utf-8 -*-
"""
web/demo_manager.py — Discovery and Safe File Management for VITAL Demos

Features:
  - Scans workspace for all actual .vital files (examples/, src/tests/, src/low/, etc.)
  - Categorizes them by language (English, Hindi, Telugu, Bengali, Marathi, Nepali, Fusion)
  - Categorizes them by project structure / difficulty
  - Extracts title and metadata from comments
  - Enforces strict path traversal security
"""

import os
import glob
from typing import Dict, List, Any, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES_DIR = os.path.join(PROJECT_ROOT, 'examples')
SRC_DIR = os.path.join(PROJECT_ROOT, 'src')

# Mapping for language identification
LANGUAGE_INDICATORS = {
    'Nepali': ['टिप्पणी_गर', 'सुरु', 'समाप्त_गर', 'कार्य_गर', 'फिर्ता', 'छाप', 'सोध', 'राख', 'नत्र', 'जबसम्म', 'रोक'],
    'Marathi': ['टीप', 'संपले', 'कार्य_करा', 'परत_करा', 'दाखवा', 'लिहा', 'विचारा', 'घ्या', 'आहे', 'नाहीतर', 'जोपर्यंत', 'जोडा'],
    'Bengali': ['মন্তব্য', 'শুরু', 'শেষ', 'ফাংশন', 'ফেরত', 'ছাপাও', 'ধরো', 'যদি', 'নাহলে', 'যতক্ষণ'],
    'Telugu': ['వ్యాఖ్య', 'ప్రారంభించు', 'ముగించు', 'రాయి', 'అనుకో', 'ఒకవేళ', 'కాకపోతే', 'ఉన్నంతవరకు', 'కలుపు'],
    'Hindi': ['टिप्पणी', 'शुरू', 'समाप्त', 'लिखो', 'छापो', 'मानो', 'अगर', 'अन्यथा', 'जबतक', 'जोड़']
}


def detect_file_language(content: str, filepath: str) -> str:
    """Detects the primary language of a .vital file."""
    norm_path = filepath.replace('\\', '/').lower()
    
    # Path-based or explicit language hint
    for lang in ['english', 'hindi', 'telugu', 'bengali', 'marathi', 'nepali']:
        if f'/{lang}/' in norm_path or f'_{lang}.' in norm_path or norm_path == lang or norm_path.startswith(lang):
            return lang.capitalize()

    # Check for Multilingual Fusion (complex benchmarks mixing multiple scripts)
    if '/complex/' in norm_path or 'comp_' in norm_path:
        return 'Multilingual Fusion'

    # Check Devanagari specific (Nepali vs Marathi vs Hindi)
    if 'टिप्पणी_गर' in content or any(w in content for w in LANGUAGE_INDICATORS['Nepali']):
        return 'Nepali'
    if 'टीप' in content or any(w in content for w in LANGUAGE_INDICATORS['Marathi']):
        return 'Marathi'
    
    # Check Unicode script ranges
    has_bengali = any(0x0980 <= ord(c) <= 0x09FF for c in content)
    has_telugu = any(0x0C00 <= ord(c) <= 0x0C7F for c in content)
    has_devanagari = any(0x0900 <= ord(c) <= 0x097F for c in content)

    if has_bengali and not has_telugu and not has_devanagari:
        return 'Bengali'
    if has_telugu and not has_bengali and not has_devanagari:
        return 'Telugu'
    if has_devanagari and not has_telugu and not has_bengali:
        return 'Hindi'
    
    if (has_telugu and has_devanagari) or (has_telugu and has_bengali):
        return 'Multilingual Fusion'

    return 'English'


def extract_file_title(content: str, filename: str) -> str:
    """Extracts a human-friendly title from the first comment or filename."""
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue

        # Strip comment prefixes
        for prefix in ['//', '#', 'टिप्पणी_गर', 'टिप्पणी', 'వ్యాఖ్య', 'মন্তব্য', 'टीप']:
            if line.startswith(prefix):
                raw_title = line[len(prefix):].strip()
                # Skip top-level educational disclaimer banner line to find specific demo name
                if 'INTENTIONALLY VULNERABLE' in raw_title:
                    continue
                # Clean language tags like "English: " or "हिंदी: "
                if ':' in raw_title:
                    parts = raw_title.split(':', 1)
                    return parts[1].strip()
                return raw_title

    # Fallback to cleaned filename
    clean_name = os.path.splitext(filename)[0].replace('_', ' ').capitalize()
    return clean_name


def get_all_demos() -> Dict[str, Any]:
    """
    Discovers all .vital demo files across the project and organizes them
    both by language and by category/folder.
    """
    try:
        from web.security_lab_registry import get_security_lab_demo_by_path
    except ImportError:
        get_security_lab_demo_by_path = lambda p: None

    all_files = []
    
    # 1. Search in examples/
    if os.path.exists(EXAMPLES_DIR):
        all_files.extend(glob.glob(os.path.join(EXAMPLES_DIR, '**', '*.vital'), recursive=True))

    # 2. Search in src/
    if os.path.exists(SRC_DIR):
        all_files.extend(glob.glob(os.path.join(SRC_DIR, '**', '*.vital'), recursive=True))

    # Deduplicate and sort
    seen_relpaths = set()
    demos_list = []

    for full_path in sorted(all_files):
        rel_path = os.path.relpath(full_path, PROJECT_ROOT).replace('\\', '/')
        if rel_path in seen_relpaths:
            continue
        seen_relpaths.add(rel_path)

        # Exclude everything under examples/saved/working_copies from the demo catalog
        if 'examples/saved/working_copies' in rel_path or '/working_copies/' in f'/{rel_path}/':
            continue

        filename = os.path.basename(full_path)
        try:
            with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except Exception:
            content = ""

        language = detect_file_language(content, full_path)
        title = extract_file_title(content, filename)

        # Lookup in Security Lab registry if applicable
        reg_entry = get_security_lab_demo_by_path(rel_path)
        is_user_saved = ('/saved/' in rel_path or '/user/' in rel_path or rel_path.startswith('examples/saved') or '_fixed.vital' in rel_path.lower())
        is_sec_lab = (not is_user_saved) and ((reg_entry is not None) or ('security_lab' in rel_path.lower()))

        # Determine category
        if is_user_saved:
            category = "My Saved Programs"
        elif is_sec_lab:
            category = "Security Lab"
        elif rel_path.startswith('examples/'):
            category = "Canonical Examples"
        elif '/tests/' in rel_path:
            category = "Cross-Language Equivalence"
        elif '/low/' in rel_path:
            category = "Benchmark: Low Complexity"
        elif '/med/' in rel_path:
            category = "Benchmark: Medium Complexity"
        elif '/high/' in rel_path:
            category = "Benchmark: High Complexity"
        elif '/complex/' in rel_path:
            category = "Benchmark: Complex Fusion"
        else:
            category = "Interactive Demos"

        demo_item = {
            "id": rel_path,
            "filename": filename,
            "path": rel_path,
            "language": language,
            "title": (title if is_user_saved else (reg_entry.title if reg_entry else title)),
            "category": category,
            "is_security_lab": is_sec_lab,
            "difficulty": "Standard" if is_user_saved else (reg_entry.difficulty if reg_entry else "Standard"),
            "scenario_type": "" if is_user_saved else (reg_entry.scenario_type if reg_entry else ""),
            "defect_categories": [] if is_user_saved else (reg_entry.defect_categories if reg_entry else []),
            "expected_findings_count": 0 if is_user_saved else (len(reg_entry.expected_findings) if reg_entry else 0),
            "lines_count": len(content.splitlines()),
            "size_bytes": len(content.encode('utf-8'))
        }
        demos_list.append(demo_item)

    # Group by Language
    languages_order = ['English', 'Hindi', 'Telugu', 'Bengali', 'Marathi', 'Nepali', 'Multilingual Fusion']
    by_language = {lang: [] for lang in languages_order}
    for item in demos_list:
        lang = item['language']
        if lang not in by_language:
            by_language[lang] = []
        by_language[lang].append(item)

    # Group by Category (Security Lab placed first for educational priority)
    categories_order = [
        "Security Lab",
        "My Saved Programs",
        "Canonical Examples",
        "Cross-Language Equivalence",
        "Benchmark: Low Complexity",
        "Benchmark: Medium Complexity",
        "Benchmark: High Complexity",
        "Benchmark: Complex Fusion",
        "Interactive Demos"
    ]
    by_category = {cat: [] for cat in categories_order}
    for item in demos_list:
        cat = item['category']
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(item)

    # Alias for backward compatibility with tests/code expecting "User Saved Programs"
    by_category["User Saved Programs"] = by_category["My Saved Programs"]

    return {
        "total_count": len(demos_list),
        "demos": demos_list,
        "by_language": by_language,
        "by_category": by_category,
        "languages_order": languages_order,
        "categories_order": [c for c in categories_order if by_category.get(c)]
    }


def get_demo_content(relative_path: str) -> Dict[str, Any]:
    """
    Safely retrieves the content of a demo file with path traversal protection.
    """
    if not relative_path:
        return {"success": False, "error": "No file path specified"}

    # Normalize and prevent directory traversal
    norm_rel = os.path.normpath(relative_path).lstrip('\\/')
    full_path = os.path.abspath(os.path.join(PROJECT_ROOT, norm_rel))

    # Security check: must reside inside PROJECT_ROOT
    try:
        common = os.path.commonpath([full_path, PROJECT_ROOT])
    except ValueError:
        return {"success": False, "error": "Invalid file path (cross-drive access denied)"}

    if common != PROJECT_ROOT or not os.path.exists(full_path) or not os.path.isfile(full_path):
        return {"success": False, "error": f"File not found or access denied: {relative_path}"}

    # Only allow reading .vital files
    if not full_path.endswith('.vital'):
        return {"success": False, "error": "Only .vital source files may be accessed"}

    try:
        try:
            from web.working_source_manager import working_source_manager
            lang_hint = detect_file_language("", full_path)
            ws_data = working_source_manager.get_working_source(norm_rel, language=lang_hint)
            code = ws_data.get("code", "")
            original_code = ws_data.get("original_code", code)
            source_revision = ws_data.get("source_revision", 1)
            content_hash = ws_data.get("content_hash", "")
            is_dirty = ws_data.get("is_dirty", False)
            is_modified = ws_data.get("is_modified", False)
            undo_count = ws_data.get("undo_count", 0)
            corrupted_discarded = ws_data.get("corrupted_discarded", False)
            notice_msg = ws_data.get("notice", "")
        except Exception:
            with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
                code = f.read()
            original_code = code
            source_revision = 1
            content_hash = ""
            is_dirty = False
            is_modified = False
            undo_count = 0
            corrupted_discarded = False
            notice_msg = ""
        
        language = detect_file_language(code, full_path)
        filename = os.path.basename(full_path)
        title = extract_file_title(code, filename)

        try:
            from web.security_lab_registry import get_security_lab_demo_by_path
            reg_entry = get_security_lab_demo_by_path(norm_rel)
        except ImportError:
            reg_entry = None

        res = {
            "success": True,
            "filename": filename,
            "path": norm_rel.replace('\\', '/'),
            "language": language,
            "title": reg_entry.title if reg_entry else title,
            "code": code,
            "original_code": original_code,
            "source_revision": source_revision,
            "content_hash": content_hash,
            "is_dirty": is_dirty,
            "is_modified": is_modified,
            "undo_count": undo_count,
            "corrupted_discarded": corrupted_discarded if 'corrupted_discarded' in locals() else False,
            "notice": notice_msg if 'notice_msg' in locals() else "",
            "is_security_lab": reg_entry is not None or "security_lab" in norm_rel.lower(),
        }
        if reg_entry:
            res["security_lab_meta"] = reg_entry.to_dict()
            res["difficulty"] = reg_entry.difficulty
            res["scenario_type"] = reg_entry.scenario_type
            res["defect_categories"] = reg_entry.defect_categories
            res["expected_findings_count"] = len(reg_entry.expected_findings)

        return res
    except Exception as e:
        return {"success": False, "error": f"Failed to read file: {str(e)}"}
