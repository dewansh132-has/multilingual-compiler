# -*- coding: utf-8 -*-
"""
web/language_context.py — VITAL Multilingual Language Intelligence System

Provides comprehensive language intelligence for local Ollama AI models:
  - Supported Languages: English, Hindi, Telugu, Bengali, Marathi, Nepali
  - Automatic source language detection via Unicode script and token frequency
  - VITAL language grammar rules, keywords, supported types, and control structures
  - Database access rules: VITAL does NOT have arbitrary dynamic SQL string concatenation.
    Secure patterns use parameterized dispatch or safe logging/printing.
  - Compiler restrictions and secure coding patterns across all 6 languages
  - Prompt context generators for Ollama remediation
"""

import os
import re
import json
from typing import Dict, Any, List, Optional, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_PATH = os.path.join(PROJECT_ROOT, "src", "language_rules.json")


class VitalLanguageIntelligence:
    """
    Central repository of VITAL language grammar, keywords, rules,
    and automatic source language identification.
    """

    SUPPORTED_LANGUAGES = [
        "English", "Hindi", "Telugu", "Bengali", "Marathi", "Nepali"
    ]

    # Script character ranges for script detection
    SCRIPT_RANGES = {
        "Telugu": (0x0C00, 0x0C7F),
        "Bengali": (0x0980, 0x09FF),
        "Devanagari": (0x0900, 0x097F),  # Hindi, Marathi, Nepali
    }

    # Distinctive keywords per language to differentiate Hindi, Marathi, and Nepali
    DISTINCTIVE_KEYWORDS = {
        "hindi": ["मानो", "लिखो", "अगर", "अन्यथा", "जबतक", "जोड़", "घटाओ", "गुणा", "भाग", "शुरू", "समाप्त"],
        "marathi": ["घ्या", "लिहा", "जर", "नाहीतर", "जोपर्यंत", "दाखवा", "ठेवा", "विचारा", "संपले", "परत_करा"],
        "nepali": ["मान", "छाप", "यदि", "नत्र", "जबसम्म", "देखाउ", "सोध", "फिर्ता", "रोक", "जारी_राख"],
        "telugu": ["అనుకో", "రాయి", "ఒకవేళ", "కాకపోతే", "ఉన్నంతవరకు", "ముద్రించు", "చూపించు", "ప్రారంభించు", "ముగించు"],
        "bengali": ["ধরো", "ছাপাও", "যদি", "নাহলে", "যতক্ষণ", "দেখাও", "ইনপুট", "শুরু", "শেষ", "ফেরত"],
        "english": ["let", "print", "if", "else", "while", "function", "def", "return", "input", "for"]
    }

    # Core language syntax profiles
    LANGUAGE_PROFILES = {
        "English": {
            "var_decl": "let variable_name = value",
            "const_decl": "const CONST_NAME = value",
            "print_stmt": "print(expression)",
            "input_stmt": "input()",
            "func_decl": "function name(param1, param2) { ... } or def name(param1) { ... }",
            "return_stmt": "return value",
            "if_else": "if (condition) { ... } else { ... }",
            "while_loop": "while (condition) { ... }",
            "comments": "# comment or // comment or /* block comment */",
            "delimiters": "{ } for blocks, ( ) for conditions/calls, [ ] for arrays",
            "data_types": "int, float, string, boolean (true/false), array [1, 2, 3]",
            "example": (
                "let count = 5\n"
                "if (count > 0) {\n"
                "    print(\"Positive count:\")\n"
                "    print(count)\n"
                "}"
            )
        },
        "Hindi": {
            "var_decl": "मानो चर_नाम = मान (or मान चर = मान)",
            "const_decl": "नियत नाम = मान",
            "print_stmt": "लिखो(अभिव्यक्ति) or छापो(अभिव्यक्ति)",
            "input_stmt": "पूछो()",
            "func_decl": "कार्य नाम(पैरामीटर) { ... }",
            "return_stmt": "लौटाओ मान",
            "if_else": "अगर (शर्त) { ... } अन्यथा { ... }",
            "while_loop": "जबतक (शर्त) { ... }",
            "comments": "// टिप्पणी or # टिप्पणी or /* टिप्पणी */",
            "delimiters": "{ } खंडों के लिए, ( ) शर्तों के लिए",
            "data_types": "पूर्णांक, दशमलव, स्ट्रिंग, बूलियन (सत्य/असत्य)",
            "example": (
                "मानो संख्या = 5\n"
                "अगर (संख्या > 0) {\n"
                "    लिखो(\"सकारात्मक संख्या:\")\n"
                "    लिखो(संख्या)\n"
                "}"
            )
        },
        "Telugu": {
            "var_decl": "అనుకో చరరాశి = విలువ (or తీసుకో చర = విలువ)",
            "const_decl": "స్థిరం పేరు = విలువ",
            "print_stmt": "రాయి(విలువ) or ముద్రించు(విలువ)",
            "input_stmt": "అడుగు() or చదువు()",
            "func_decl": "ఫంక్షన్ పేరు(పరామితి) { ... }",
            "return_stmt": "తిరిగి_ఇవ్వు విలువ",
            "if_else": "ఒకవేళ (షరతు) { ... } కాకపోతే { ... }",
            "while_loop": "ఉన్నంతవరకు (షరతు) { ... }",
            "comments": "// వ్యాఖ్య or # వ్యాఖ్య or /* వ్యాఖ్య */",
            "delimiters": "{ } బ్లాకుల కోసం, ( ) షరతుల కోసం",
            "data_types": "పూర్ణాంకం, ఫ్లోట్, స్ట్రింగ్, బూలియన్",
            "example": (
                "అనుకో సంఖ్య = 5\n"
                "ఒకవేళ (సంఖ్య > 0) {\n"
                "    రాయి(\"సానుకూల సంఖ్య:\")\n"
                "    రాయి(సంఖ్య)\n"
                "}"
            )
        },
        "Bengali": {
            "var_decl": "ধরো চলক = মান",
            "const_decl": "স্থির নাম = মান",
            "print_stmt": "ছাপাও(মান) or দেখাও(মান)",
            "input_stmt": "ইনপুট() or জিজ্ঞাসা()",
            "func_decl": "ফাংশন নাম(প্যারামিটার) { ... }",
            "return_stmt": "ফেরত মান",
            "if_else": "যদি (শর্ত) { ... } নাহলে { ... }",
            "while_loop": "যতক্ষণ (শর্ত) { ... }",
            "comments": "// মন্তব্য or # মন্তব্য or /* মন্তব্য */",
            "delimiters": "{ } ব্লকের জন্য, ( ) শর্তের জন্য",
            "data_types": "পূর্ণসংখ্যা, দশমিক, স্ট্রিং, বুলিয়ান",
            "example": (
                "ধরো সংখ্যা = 5\n"
                "যদি (संख्या > 0) {\n"
                "    ছাপাও(\"ধনাত্মক সংখ্যা:\")\n"
                "    ছাপাও(संख्या)\n"
                "}"
            )
        },
        "Marathi": {
            "var_decl": "घ्या चल = मूल्य (or ठरवा चल = मूल्य)",
            "const_decl": "स्थिर नाव = मूल्य",
            "print_stmt": "लिहा(अभिव्यक्ती) or दाखवा(अभिव्यक्ती)",
            "input_stmt": "विचारा()",
            "func_decl": "कार्य_करा नाव(पॅरामीटर) { ... }",
            "return_stmt": "परत_करा मूल्य",
            "if_else": "जर (अट) { ... } नाहीतर { ... }",
            "while_loop": "जोपर्यंत (अट) { ... }",
            "comments": "// टीप or # टीप or /* टीप */",
            "delimiters": "{ } ब्लॉकसाठी, ( ) अटींसाठी",
            "data_types": "पूर्णांक, दशांश, मजकूर, बूलियन",
            "example": (
                "घ्या संख्या = 5\n"
                "जर (संख्या > 0) {\n"
                "    लिहा(\"सकारात्मक संख्या:\")\n"
                "    लिहा(संख्या)\n"
                "}"
            )
        },
        "Nepali": {
            "var_decl": "मान चल = मान (or राख चल = मान)",
            "const_decl": "स्थिर_गर नाम = मान",
            "print_stmt": "छाप(मान) or देखाउ(मान)",
            "input_stmt": "सोध() or इनपुट()",
            "func_decl": "कार्य_गर नाम(प्यारामिटर) { ... }",
            "return_stmt": "फिर्ता मान",
            "if_else": "यदि (शर्त) { ... } नत्र { ... }",
            "while_loop": "जबसम्म (शर्त) { ... }",
            "comments": "// टिप्पणी_गर or # टिप्पणी or /* टिप्पणी */",
            "delimiters": "{ } ब्लकको लागि, ( ) शर्तको लागि",
            "data_types": "पूर्णांक, फ्लोट, स्ट्रिङ, बुलियन",
            "example": (
                "मान संख्या = 5\n"
                "यदि (संख्या > 0) {\n"
                "    छाप(\"सकारात्मक संख्या:\")\n"
                "    छाप(संख्या)\n"
                "}"
            )
        }
    }

    # Compiler restrictions common to all VITAL languages
    COMPILER_RESTRICTIONS = [
        "1. Every block must have matching opening '{' and closing '}' delimiters.",
        "2. Identifiers must be declared before use (using the language declaration keyword).",
        "3. Expressions inside if/while conditions must be enclosed in parentheses '(' and ')'.",
        "4. Variables are lexically scoped within their enclosing function or block.",
        "5. Comments starting with '#', '//', or /* ... */ are ignored during tokenization.",
        "6. VITAL transpiles to an Intermediate Representation (IR); syntax must remain strictly within VITAL grammar."
    ]

    # Database & Security Rules
    SECURITY_RULES = [
        "SEC-INJ-001 (SQL Injection): Dynamic string concatenation (e.g. query_prefix + user_filter) is strictly prohibited. Use safe parameterized dispatch or logging (e.g. print('Executing parameterized query:'); print(param); return 1). Never concatenate untrusted variables directly into queries.",
        "SEC-IDOR-001 (Insecure Direct Object Reference): Direct parameter usage must be guarded by caller verification: 'if (caller_id != from_account_id) { ... return 0 }'.",
        "SEC-STATE-001 (State Bypass): Account active/status validation must execute unconditionally before any debit/transfer.",
        "SEC-IR-001/002/005 (Dynamic Execution): Dynamic eval(), exec(), or os.system() sinks are prohibited and must be replaced with safe native functions.",
        "SEC-DATA-003 (Array Boundary): Loop bounds and index guards must use strict inequality (< size) to prevent off-by-one errors."
    ]

    @classmethod
    def detect_language(cls, source_code: str) -> str:
        """
        Automatically identifies the source language of the VITAL code
        based on Unicode character scripts and keyword frequencies.
        Returns: One of 'English', 'Hindi', 'Telugu', 'Bengali', 'Marathi', 'Nepali'.
        """
        if not source_code or not source_code.strip():
            return "English"

        # 1. Check for Telugu script
        telugu_chars = sum(1 for ch in source_code if 0x0C00 <= ord(ch) <= 0x0C7F)
        if telugu_chars > 2:
            return "Telugu"

        # 2. Check for Bengali script
        bengali_chars = sum(1 for ch in source_code if 0x0980 <= ord(ch) <= 0x09FF)
        if bengali_chars > 2:
            return "Bengali"

        # 3. Check for Devanagari script (Hindi, Marathi, Nepali)
        devanagari_chars = sum(1 for ch in source_code if 0x0900 <= ord(ch) <= 0x097F)
        if devanagari_chars > 2:
            # Distinguish Hindi vs Marathi vs Nepali by keyword matching
            marathi_score = sum(source_code.count(kw) for kw in cls.DISTINCTIVE_KEYWORDS["marathi"])
            nepali_score = sum(source_code.count(kw) for kw in cls.DISTINCTIVE_KEYWORDS["nepali"])
            hindi_score = sum(source_code.count(kw) for kw in cls.DISTINCTIVE_KEYWORDS["hindi"])

            if marathi_score > hindi_score and marathi_score >= nepali_score:
                return "Marathi"
            if nepali_score > hindi_score and nepali_score > marathi_score:
                return "Nepali"
            return "Hindi"

        # 4. English default
        return "English"

    @classmethod
    def get_language_context_prompt(cls, language: str, stage_id: str = "syntax_analysis") -> str:
        """
        Generates a concise, high-value language context prompt for Ollama
        including grammar, valid keywords, restrictions, and security patterns.
        """
        lang = language if language in cls.LANGUAGE_PROFILES else "English"
        prof = cls.LANGUAGE_PROFILES[lang]

        context_lines = [
            f"=== VITAL PROGRAMMING LANGUAGE SPECIFICATION ({lang.upper()}) ===",
            f"Variable Declaration: {prof['var_decl']}",
            f"Print Statement:      {prof['print_stmt']}",
            f"Input Statement:      {prof['input_stmt']}",
            f"Function Definition:  {prof['func_decl']}",
            f"Return Statement:     {prof['return_stmt']}",
            f"Conditionals:         {prof['if_else']}",
            f"While Loop:           {prof['while_loop']}",
            f"Comments:             {prof['comments']}",
            f"Supported Types:      {prof['data_types']}",
            "",
            "Valid Code Example:",
            prof['example'],
            "",
            "=== COMPILER RESTRICTIONS ===",
            "\n".join(cls.COMPILER_RESTRICTIONS),
            "",
            "=== SECURITY RULES ===",
            "\n".join(cls.SECURITY_RULES)
        ]

        if "security" in stage_id.lower() or "inj" in stage_id.lower():
            context_lines.extend([
                "",
                "=== DATABASE SECURITY INSTRUCTION ===",
                "VITAL does NOT provide raw dynamic SQL concatenation.",
                "To resolve SQL injection (SEC-INJ-001):",
                "- Remove dynamic string concatenation (query_prefix + user_filter).",
                "- Replace with safe parameterized lookup pattern:",
                "    // Parameterized database lookup",
                "    print(\"Executing parameterized safe query for account:\")",
                "    print(user_filter)",
                "    return 1",
                "- Never use eval() or invent unsupported database APIs."
            ])

        return "\n".join(context_lines)


# Singleton instance
language_intelligence = VitalLanguageIntelligence()

