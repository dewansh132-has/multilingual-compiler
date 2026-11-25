# VITAL Multilingual Programming Language Compiler & Web IDE

VITAL is an educational and verifiable multilingual programming language and compiler system. It allows software logic to be authored, compiled, optimized, analyzed, and executed in **six languages** across distinct scripts:
- **English** (Latin)
- **Hindi** (Devanagari)
- **Telugu** (Telugu)
- **Bengali** (Bengali)
- **Marathi** (Devanagari)
- **Nepali** (Devanagari)

---

## 🌟 Key Features

1. **Universal Multi-Script Lexer & Parser**: Single-pass lexical scanner with Unicode homoglyph normalization, indentation tracking, and strict delimiter validation (`src/lexer.py`, `src/parser.py`).
2. **14-Stage Verified Compiler Pipeline**: Full pedagogical visibility across lexical analysis, syntax parsing, visual AST, semantic symbol tables, IR generation, optimization, security checks, sandboxed execution, and final reporting (`web/pipeline_tracker.py`).
3. **Mandatory 5-Pass IR Optimization**: Constant folding, constant propagation, dead code elimination, redundant operation removal, and algebraic simplification with formal mathematical proof logs (`web/ir_optimizer.py`).
4. **Security Vulnerability Scanner & Remediation**: Real-time detection of CWE-89 (SQL Injection), CWE-798 (Hardcoded Credentials), CWE-94 (Command Injection), and timing vulnerabilities (`web/security_analyzer.py`).
5. **AI-Powered Code Remediation**:
   - Automated remediation proposals with non-destructive unified diffs and whole-buffer validation (`web/ai_remediation_engine.py`).
   - Powered by Google Gemini API (`gemini-2.5-flash`) with 100% offline fallback to deterministic compiler rules.

---

## 🚀 Quickstart & Setup

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.11, 3.12, 3.14)
- Google Chrome, Edge, or modern web browser

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Gemini AI API Key
1. Obtain a free API key from [Google AI Studio](https://aistudio.google.com/apikey).
2. Copy the sample environment file:
   ```bash
   cp .env.example .env
   ```
3. Edit `.env` and paste your key:
   ```env
   GEMINI_API_KEY=your_actual_key_here
   GEMINI_MODEL_FAST=gemini-2.5-flash
   GEMINI_MODEL_ADVANCED=gemini-2.5-flash
   VITAL_AI_TIMEOUT=45
   ```

> **Note on Offline / Zero-Config Execution**:
> Setting an API key is completely optional. If `GEMINI_API_KEY` is not configured or network access is unavailable, VITAL automatically falls back to local deterministic compiler rules. All compiler stages, demo executions, and security diagnostics remain 100% functional.

### 4. Launch the Web IDE
```bash
python app.py
```

Then open your browser to:
```text
http://localhost:8000
```

---

## 🛠️ Project Structure

```text
multilingual_compiler/
├── app.py                     # Web IDE entry point with .env loader & startup banner
├── requirements.txt           # Project dependencies (Flask, python-dotenv, etc.)
├── .env.example               # Environment variable configuration template
├── src/                       # Core compiler engine
│   ├── lexer.py               # Multilingual lexical analyzer & homoglyph detector
│   ├── parser.py              # Recursive-descent AST parser & delimiter stack
│   ├── semantic.py            # Scope checker & symbol table manager
│   ├── codegen.py             # Python intermediate representation emitter
│   ├── main.py                # Standalone Compiler pipeline coordinator
│   └── gui.py                 # Legacy desktop Tkinter GUI
├── web/                       # Modern Web IDE & Flask Backend
│   ├── server.py              # REST API endpoints (/api/run, /api/security, /api/ai)
│   ├── gemini_client.py       # Google Gemini REST client (replaces local Ollama)
│   ├── ai_remediation_engine.py # Multi-model remediation engine & patch validator
│   ├── ir_optimizer.py        # 5-pass IR optimization engine & proof generator
│   ├── security_analyzer.py   # Deterministic CWE security vulnerability scanner
│   ├── pipeline_tracker.py    # 14-stage pipeline definitions & metrics
│   ├── working_source_manager.py # Immutable working buffer manager
│   ├── templates/index.html   # Main Web IDE interface
│   └── static/                # CodeMirror, CSS styles, and IDE application logic
├── examples/                  # Multilingual sample code in 6 languages
└── tests/                     # Automated test suites & regression tests
```

---

## 📜 Changelog & Evolution

- **Milestone 1 (Transpiler Prototype)**: Initial AST transpiler and Tkinter desktop GUI (`src/gui.py`).
- **Milestone 2 (6-Language Lexer)**: Expanded lexical and grammar support to English, Hindi, Telugu, Bengali, Marathi, and Nepali.
- **Milestone 3 (Web IDE Architecture)**: Flask browser IDE with CodeMirror syntax highlighting and real-time execution.
- **Milestone 4 (14-Stage Verified Pipeline)**: 14 distinct pedagogical compilation stages and 5-pass IR optimizer.
- **Milestone 5 (Security Lab & Vulnerability Rules)**: Deterministic CWE detection engine and security demo testbed.
- **Milestone 6 (Local AI Remediation - Historical)**: Local Ollama LLM integration for AI-assisted diagnostic fixes.
- **Milestone 7 (Migrated from local Ollama to Gemini API)**: Migrated from local Ollama daemon to Google Gemini API (`gemini-2.5-flash`). Eliminated CPU latency (15–60s down to <1s), removed 86% RAM memory pressure and model swapping overhead, enabled `.env` configuration, and reinforced deterministic local fallback guarantees.
