import json

f1_data = {
    "title": "Figure 1. Conventional Disconnected Educational Compiler Architecture",
    "canvas": {
        "width_emu": 5943600,
        "height_emu": 3600000
    },
    "categories": {
        "standard": {
            "fill": "FFFFFF",
            "stroke": "000000",
            "text": "000000"
        },
        "gap": {
            "fill": "FFFFFF",
            "stroke": "000000",
            "text": "000000",
            "dash": "dash"
        }
    },
    "boxes": [
        {
            "id": "box_student",
            "name": "Box_Student",
            "category": "standard",
            "x": 200000,
            "y": 100000,
            "width": 2600000,
            "height": 480000,
            "shape_type": "rect",
            "font_size": 8.0,
            "bold": True,
            "text": "Novice Student / Programmer\nManual code authoring & local debugging loop"
        },
        {
            "id": "box_source",
            "name": "Box_Source",
            "category": "standard",
            "x": 200000,
            "y": 800000,
            "width": 2600000,
            "height": 480000,
            "shape_type": "rect",
            "font_size": 8.0,
            "bold": True,
            "text": "Source Code\nRestricted strictly to English keywords"
        },
        {
            "id": "box_compiler",
            "name": "Box_Compiler",
            "category": "standard",
            "x": 200000,
            "y": 1500000,
            "width": 2600000,
            "height": 520000,
            "shape_type": "rect",
            "font_size": 7.5,
            "bold": True,
            "text": "Conventional Compiler Pipeline\n(Lexer -> Parser -> Semantic -> CodeGen)\nOpaque black box; no intermediate stage visibility"
        },
        {
            "id": "box_execution",
            "name": "Box_Execution",
            "category": "standard",
            "x": 200000,
            "y": 2250000,
            "width": 2600000,
            "height": 480000,
            "shape_type": "rect",
            "font_size": 7.5,
            "bold": True,
            "text": "Ungated Runtime Execution\nCompiles & executes vulnerable code directly;\nuncaught crashes or runtime security violations"
        },
        {
            "id": "box_gap1",
            "name": "Box_Gap1",
            "category": "gap",
            "dash": True,
            "x": 3100000,
            "y": 800000,
            "width": 2650000,
            "height": 480000,
            "shape_type": "rect",
            "font_size": 7.5,
            "bold": True,
            "text": "[RESEARCH GAP 1: Linguistic Exclusion]\nNo native Indic script / multilingual support;\nimposes cognitive penalty on non-English novices"
        },
        {
            "id": "box_gap2",
            "name": "Box_Gap2",
            "category": "gap",
            "dash": True,
            "x": 3100000,
            "y": 1500000,
            "width": 2650000,
            "height": 520000,
            "shape_type": "rect",
            "font_size": 7.5,
            "bold": True,
            "text": "[RESEARCH GAP 2: Opaque Transformation]\nZero student visibility into AST, IR, or symbol tables;\nno step-by-step optimization proof logs"
        },
        {
            "id": "box_gap3",
            "name": "Box_Gap3",
            "category": "gap",
            "dash": True,
            "x": 3100000,
            "y": 2250000,
            "width": 2650000,
            "height": 480000,
            "shape_type": "rect",
            "font_size": 7.5,
            "bold": True,
            "text": "[RESEARCH GAP 3: Absent Policy Gating]\nNo automated security barrier prior to runtime;\nmalicious or vulnerable payloads execute freely"
        },
        {
            "id": "box_gap4",
            "name": "Box_Gap4",
            "category": "gap",
            "dash": True,
            "x": 200000,
            "y": 2950000,
            "width": 5550000,
            "height": 550000,
            "shape_type": "rect",
            "font_size": 7.5,
            "bold": True,
            "text": "[RESEARCH GAP 4: Disconnected & Unverified Remediation]\nStudents manually copy compiler errors into disconnected external LLM chats or third-party linters;\nsuggested patches frequently hallucinate syntax errors, alter program semantics, or introduce regressions."
        }
    ],
    "arrows": [
        {"from": "box_student", "to": "box_source", "label": "Writes"},
        {"from": "box_source", "to": "box_compiler", "label": "Compiles"},
        {"from": "box_compiler", "to": "box_execution", "label": "Direct Run"},
        {"from": "box_execution", "to": "box_gap4", "label": "Crash / Bug"},
        {"from": "box_source", "to": "box_gap1", "label": "Exclusion"},
        {"from": "box_compiler", "to": "box_gap2", "label": "Opacity"},
        {"from": "box_execution", "to": "box_gap3", "label": "No Gate"}
    ]
}

with open("docs/report_data/architecture_figure1.json", "w", encoding="utf-8") as f:
    json.dump(f1_data, f, indent=2)

f2_data = {
    "title": "Figure 2. Proposed VITAL 14-Stage Security-Gated Architecture",
    "canvas": {
        "width_emu": 8229600,
        "height_emu": 4500000
    },
    "categories": {
        "standard": {
            "fill": "FFFFFF",
            "stroke": "000000",
            "text": "000000"
        },
        "gate": {
            "fill": "FFFFFF",
            "stroke": "000000",
            "text": "000000"
        }
    },
    "boxes": [
        {
            "id": "box_ide",
            "name": "Box_IDE",
            "category": "standard",
            "x": 300000,
            "y": 100000,
            "width": 3100000,
            "height": 600000,
            "shape_type": "rect",
            "font_size": 8.0,
            "bold": True,
            "text": "VITAL Web IDE (Interactive Educational Client)\nCodeMirror Multi-Script Editor | 79-Demo Catalog Explorer\nInteractive Stage Drawers | Real-Time Preflight Health & Status"
        },
        {
            "id": "box_flask_api",
            "name": "Box_Flask_API",
            "category": "standard",
            "x": 3700000,
            "y": 100000,
            "width": 2300000,
            "height": 600000,
            "shape_type": "rect",
            "font_size": 8.0,
            "bold": True,
            "text": "Flask REST / SSE Gateway (app.py)\nRevision Hashing (SHA-256) | Run Registry\nReal-Time Asynchronous SSE Streamer"
        },
        {
            "id": "box_lang_rules",
            "name": "Box_Lang_Rules",
            "category": "standard",
            "x": 6300000,
            "y": 100000,
            "width": 1600000,
            "height": 600000,
            "shape_type": "rect",
            "font_size": 7.5,
            "bold": True,
            "text": "Language Rules\n(language_rules.json)\n7 Script Lexicons\nHomoglyph Shield"
        },
        {
            "id": "box_phase1",
            "name": "Box_Phase1",
            "category": "standard",
            "x": 300000,
            "y": 900000,
            "width": 5700000,
            "height": 550000,
            "shape_type": "rect",
            "font_size": 7.5,
            "bold": True,
            "text": "PHASE 1: FRONT-END ANALYSIS (Stages 1–6)\nS1: Preflight & Normalization  ->  S2: Lexical Analysis (Homoglyph Shield)  ->  S3: Syntax Analysis (LR Grammar)\nS4: Visual AST Construction   ->  S5: Semantic Analysis (Scope Resolution)  ->  S6: Symbol Table Construction"
        },
        {
            "id": "diamond_gate1",
            "name": "Gate_Phase1",
            "category": "gate",
            "x": 6300000,
            "y": 900000,
            "width": 1600000,
            "height": 550000,
            "shape_type": "roundRect",
            "font_size": 7.5,
            "bold": True,
            "text": "[Phase 1 Gate]\nSyntax & Semantic Check\nPass / Warning / Fail"
        },
        {
            "id": "box_phase2",
            "name": "Box_Phase2",
            "category": "standard",
            "x": 300000,
            "y": 1650000,
            "width": 5700000,
            "height": 550000,
            "shape_type": "rect",
            "font_size": 7.5,
            "bold": True,
            "text": "PHASE 2: MIDDLE & BACK-END TRANSFORMATION (Stages 7–10)\nS7: Python Intermediate Representation (Transpiled AST)  ->  S8: 5-Pass IR Optimizer (Auditable Proof Logs)\nS9: Target Code Generation  ->  S10: Bytecode Validation (py_compile Verification)"
        },
        {
            "id": "diamond_gate2",
            "name": "Gate_Phase2",
            "category": "gate",
            "x": 6300000,
            "y": 1650000,
            "width": 1600000,
            "height": 550000,
            "shape_type": "roundRect",
            "font_size": 7.5,
            "bold": True,
            "text": "[Phase 2 Gate]\nIR & Bytecode Audit\nPass / Warning / Fail"
        },
        {
            "id": "box_phase3",
            "name": "Box_Phase3",
            "category": "standard",
            "x": 300000,
            "y": 2400000,
            "width": 5700000,
            "height": 550000,
            "shape_type": "rect",
            "font_size": 7.5,
            "bold": True,
            "text": "PHASE 3: STATIC SECURITY ANALYSIS (Stages 11–12)\nS11: Deterministic SAST Scanner (42 Specialized Rules mapped to 21 distinct CWE classes)\nS12: Optional Cloud AI Security Corroboration (Google Gemini API: gemini-2.5-pro / flash)"
        },
        {
            "id": "diamond_sec_gate",
            "name": "Gate_Security",
            "category": "gate",
            "x": 6300000,
            "y": 2400000,
            "width": 1600000,
            "height": 550000,
            "shape_type": "roundRect",
            "font_size": 7.5,
            "bold": True,
            "text": "[Security Gate]\nPolicy Risk Threshold\nCritical / High -> BLOCK!"
        },
        {
            "id": "box_remediation",
            "name": "Box_Remediation",
            "category": "standard",
            "x": 300000,
            "y": 3200000,
            "width": 4100000,
            "height": 700000,
            "shape_type": "rect",
            "font_size": 7.5,
            "bold": True,
            "text": "CLOSED-LOOP REMEDIATION ENGINE (Deterministic-First AI Architecture)\n1. Issue Collector: Aggregates syntax, semantic, and security findings across all stages\n2. Deterministic Fixer Registry: Applies verified rule-specific AST repair templates\n3. AI Remediation Fallback: Gemini cloud scoped single-hunk unified diff generation\n4. Copy Verification: Multi-pass re-compilation on isolated working copies prior to buffer commit"
        },
        {
            "id": "box_execution",
            "name": "Box_Execution",
            "category": "standard",
            "x": 4700000,
            "y": 3200000,
            "width": 3200000,
            "height": 700000,
            "shape_type": "rect",
            "font_size": 7.5,
            "bold": True,
            "text": "PHASES 4 & 5: ISOLATED EXECUTION & TELEMETRY (Stages 13–14)\nStage 13: Fortified Sandbox (5.0s timeout, 200k char cap, blocked syscalls)\nStage 14: Comprehensive Pipeline Telemetry Report (Audit Timings & Statuses)"
        }
    ],
    "arrows": [
        {"from": "box_ide", "to": "box_flask_api", "label": "Compile Request"},
        {"from": "box_flask_api", "to": "box_phase1", "label": "Dispatch S1"},
        {"from": "box_lang_rules", "to": "diamond_gate1", "label": "Rules"},
        {"from": "box_phase1", "to": "diamond_gate1", "label": "Artifacts"},
        {"from": "diamond_gate1", "to": "diamond_gate2", "label": "Pass / Warn"},
        {"from": "box_phase2", "to": "diamond_gate2", "label": "Artifacts"},
        {"from": "diamond_gate2", "to": "diamond_sec_gate", "label": "Pass / Warn"},
        {"from": "box_phase3", "to": "diamond_sec_gate", "label": "Findings"},
        {"from": "diamond_sec_gate", "to": "box_execution", "label": "PASS: Run"},
        {"from": "box_phase3", "to": "box_remediation", "label": "BLOCK: Remediate"},
        {"from": "box_remediation", "to": "box_ide", "label": "Apply Patch"}
    ]
}

with open("docs/report_data/architecture_figure2.json", "w", encoding="utf-8") as f:
    json.dump(f2_data, f, indent=2)

print("Updated both JSON files with clean orthogonal alignment!")
