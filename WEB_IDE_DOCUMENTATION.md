# VITAL Multilingual Compiler — Web IDE Documentation

## 1. Why the Web IDE was Added
Previously, demonstrating the VITAL Multilingual Programming Language Compiler required running a desktop Tkinter application (`gui.py`) and manually uploading or browsing local files on the host computer. While functional for local development, this desktop workflow had significant limitations:
- It required manually searching and uploading files from the computer for every single demonstration.
- It did not provide an integrated demonstration explorer to showcase cross-language comparisons side by side.
- It lacked modern browser accessibility, remote demonstration capability, and responsive layout controls.

The **VITAL Web IDE** replaces this manual desktop workflow with a modern, browser-based IDE that runs on top of the exact same Python compiler pipeline.

---

## 2. Existing `gui.py` Workflow vs. New Web IDE Workflow

### Previous Workflow (`gui.py`):
```text
Run gui.py → Tkinter Desktop Window → File Dialog (Browse .vital file) → Run Compiler → View Logs
```

### New Web IDE Workflow:
```text
Run python app.py → Open http://localhost:8000 → Select Demo from Explorer → Live Code in Editor → Click ▶ Run → Real-time Execution & Multi-Stage Logs
```

The desktop GUI (`src/gui.py`) remains completely functional and untouched.

---

## 3. High-Level Architecture

```text
                           CLIENT BROWSER (Modern Web IDE)
                 ┌──────────────────────────────────────────────────┐
                 │  - File Explorer (By Language / By Category)     │
                 │  - Code Editor (CodeMirror with VITAL Mode)      │
                 │  - Multi-Tab Output Panel & Diagnostic Console   │
                 └─────────────────────────┬────────────────────────┘
                                           │
                                           │ REST API (HTTP / JSON)
                                           ▼
                            PYTHON BACKEND (Flask Server)
                 ┌──────────────────────────────────────────────────┐
                 │  web/server.py                                   │
                 │    ├── GET  /                 (Web IDE UI)       │
                 │    ├── GET  /api/demos        (Demo Registry)    │
                 │    ├── GET  /api/demo-content (Safe File Loader) │
                 │    └── POST /api/run          (Compile & Execute)│
                 └─────────────────────────┬────────────────────────┘
                                           │
                                           ▼
                          SAFE RUNNER (web/compiler_runner.py)
                 ┌──────────────────────────────────────────────────┐
                 │  - Subprocess Execution Isolation                │
                 │  - 5-Second Timeout Guard (Anti-Infinite Loop)   │
                 │  - UTF-8 Stream Reconfiguration                  │
                 └─────────────────────────┬────────────────────────┘
                                           │
                                           ▼
                      EXISTING VITAL COMPILER (src/main.py)
                 ┌──────────────────────────────────────────────────┐
                 │  1. Compiler.load_rules('language_rules.json')   │
                 │  2. Compiler.run_lexer()     → tests/lexer_log   │
                 │  3. Compiler.run_parser()    → tests/parser_log  │
                 │  4. Compiler.transpile()     → tests/ir.txt      │
                 │  5. Compiler.execute()       → tests/output.txt  │
                 └─────────────────────────┬────────────────────────┘
                                           │
                                           ▼
                             OUTPUTS & LOGS (tests/)
                 ┌──────────────────────────────────────────────────┐
                 │  output.txt, lexer_log.txt, parser_log.txt,      │
                 │  ast_log.txt, ir.txt, symbol_table.txt           │
                 └──────────────────────────────────────────────────┘
```

---

## 4. Frontend Architecture
The frontend is built using standard, framework-less HTML5, CSS3, and JavaScript, ensuring lightweight, high-performance, and dependable execution without fragile node build toolchains:
1. **HTML Structure (`web/templates/index.html`)**:
   - Header with Logo, Language indicator, Actions (`▶ Run`, `+ New`, `📂 Open`, `💾 Save As`, `⟳ Reset`, `Clear`, `Theme`).
   - Three-column layout:
     - **Left Panel**: Explorer with view toggle (`By Language` / `By Category`) and search filtering.
     - **Center Panel**: CodeMirror editor with filename tab, dirty dot indicator, and breadcrumb.
     - **Right Panel**: Multi-tab output console (`★ Output`, `Pipeline Report`, `1. Lexer`, `2. Parser`, `3. AST`, `4. IR (Python)`, `5. Symbol Table`).
   - Status bar displaying compiler status, elapsed time in ms, cursor line/col, encoding, and version.
2. **Design System (`web/static/css/ide.css`)**:
   - Professional dark developer-tool aesthetic (Oceanic Slate and Navy: `#0F172A`, `#1E293B`, `#334155`, `#38BDF8`, `#22D3EE`, `#1D4ED8`, `#10B981`, `#F43F5E`).
   - Resizable draggable splitters for custom panel widths.
   - Clean monospace typography for code and high-contrast terminal styling for diagnostics.
3. **Syntax Highlighting (`web/static/js/vital-mode.js`)**:
   - Custom CodeMirror mode recognizing keywords, operators, comments, strings, numbers, and identifiers across all 6 supported languages:
     - English (`let`, `print`, `if`, `while`, etc.)
     - Hindi (`मानो`, `लिखो`, `अगर`, `जबतक`, `जोड़`, etc.)
     - Telugu (`అనుకో`, `రాయి`, `ఒకవేళ`, `ఉన్నంతవరకు`, `కలుపు`, etc.)
     - Bengali (`ধরো`, `ছাপাও`, `যদি`, `যতক্ষণ`, `যোগ`, etc.)
     - Marathi (`घ्या`, `लिहा`, `जर`, `जोपर्यंत`, `जोडा`, etc.)
     - Nepali (`मान`, `छाप`, `यदि`, `जबसम्म`, `जोड`, etc.)
4. **Client State & API Controller (`web/static/js/ide.js`)**:
   - Handles demo selection, local file reading via HTML5 `FileReader`, file saving via `Blob` download, asynchronous execution, stage tab switching, and error badge highlighting.
   - Offline-capable: CodeMirror library is vendored locally in `web/static/vendor/`.

---

## 5. Backend Architecture
The backend is built with Python and Flask (`web/server.py`):
1. **Demo Manager (`web/demo_manager.py`)**:
   - Automatically scans `examples/` and `src/` to index all 60 `.vital` programs.
   - Classifies each program by language and project complexity category.
   - Enforces strict path traversal protection preventing directory escaping.
2. **Compiler Runner (`web/compiler_runner.py`)**:
   - Subprocess worker running the exact `Compiler` class from `src/main.py`.
   - Isolates execution from the web server: memory leaks, runtime crashes, or infinite loops cannot crash the server.
   - Enforces a 5.0-second execution timeout.
   - Reconfigures `sys.stdin`, `sys.stdout`, and `sys.stderr` to UTF-8 to prevent Windows surrogate-escape encoding errors on non-ASCII Indic characters.
   - Collects all generated pipeline logs (`output.txt`, `lexer_log.txt`, `parser_log.txt`, `ast_log.txt`, `ir.txt`, `symbol_table.txt`) and returns them as a structured JSON object.

---

## 6. How the Backend Invokes the Existing Compiler
The backend does **NOT** rewrite, emulate, or duplicate any compiler logic. It imports and executes:
```python
from main import Compiler, RULES_FILE

app = Compiler(RULES_FILE)
app.load_rules()

# 1. Lexical Analysis
app.run_lexer(source_code)

# 2. Parser Validation
is_valid = app.run_parser(source_code)

# 3. Transpilation & Execution
if is_valid:
    py_code = app.transpile(source_code)
    app.execute(py_code)
```
The logs generated in `tests/` are read and sent back to the browser.

---

## 7. How Demo Files are Discovered
The `get_all_demos()` function in `web/demo_manager.py`:
1. Searches `examples/**/*.vital` and `src/**/*.vital`.
2. Inspects script unicode ranges and comment markers (`//`, `टिप्पणी`, `వ్యాఖ్య`, `মন্তব্য`, `टीप`, `टिप्पणी_गर`).
3. Groups files into:
   - **By Language**: English, Hindi, Telugu, Bengali, Marathi, Nepali, and Multilingual Fusion.
   - **By Category**: Canonical Examples, Cross-Language Equivalence, Low Complexity, Medium Complexity, High Complexity, Complex Fusion, and Interactive Demos.
4. Returns the structured manifest to `/api/demos`.

---

## 8. How Editor Contents are Sent to the Compiler
When the user clicks `▶ Run` (or presses `Ctrl+Enter`):
1. `ide.js` extracts the current editor string via `editor.getValue()`.
2. Sends an HTTP POST request to `/api/run` with payload `{"code": "...", "language": "..."}`.
3. The server feeds the code string directly into the compiler runner.
4. Because the code is taken directly from the editor, **any user edits are executed immediately**, without modifying or overwriting the original files on disk.

---

## 9. Error Handling
The IDE handles errors gracefully across all layers:
- **Empty Code**: Caught on client and server; returns a clear prompt without executing.
- **Unbalanced Brackets / Syntax Errors**: Detected by `Compiler.run_parser()`; the backend returns `execution_status: "syntax_error"`, sets the status bar to red, and automatically highlights and switches to the `2. Parser` tab.
- **Runtime Errors (e.g. division by zero)**: Caught by Python's `exec()` sandbox inside `Compiler.execute()`; displayed cleanly in `output.txt` and highlighted in the `★ Output` tab.
- **Infinite Loops**: The subprocess runner terminates the process after 5.0 seconds and reports a timeout error without freezing the browser or backend.

---

## 10. Security Considerations
- **Execution Isolation**: Code execution runs in a separate child process.
- **Path Traversal Protection**: `web/demo_manager.py` verifies that all requested file paths resolve strictly inside the workspace boundary using `os.path.commonpath`.
- **Extension Restriction**: Only `.vital` files can be requested through `/api/demo-content`.
- **Safe Save Behavior**: Browser edits are never written back to disk files. If the user wants to keep modifications, they use `Save As` to download the file locally.
- **No Arbitrary OS Commands**: No shell commands or arbitrary python script execution endpoints are exposed.

---

## 11. How to Start the Web IDE
Run the following command from the workspace root:

```bash
python app.py
```

Then open your browser and navigate to:

```text
http://localhost:8000
```

---

## 12. How to Demonstrate to the Professor
Follow this quick 5-step demonstration:
1. **Show Language Equivalence**:
   - In the left Explorer, click `English` → `hello.vital` and click `▶ Run`. Point out output:
     ```text
     Hello, Multilingual VITAL!
     The value is:
     42
     ```
   - In the left Explorer, click `Hindi` → `hello.vital` and click `▶ Run`. Show that the Hindi equivalent produces the same logical output:
     ```text
     नमस्ते, बहुभाषी VITAL!
     मान है:
     42
     ```
   - Select `Telugu`, `Bengali`, `Marathi`, and `Nepali` to demonstrate all 6 languages running on the universal compiler engine.
2. **Show Compiler Pipeline Stages**:
   - Click the tabs in the right panel:
     - `1. Lexer`: Show token classification and column tracking.
     - `2. Parser`: Show syntactic validation and structure check.
     - `3. AST`: Show visual abstract syntax tree.
     - `4. IR (Python)`: Show generated Python Intermediate Representation.
     - `5. Symbol Table`: Show runtime variables, types, and values.
     - `Pipeline Report`: Show complete aggregated logs (matching `gui.py`).
3. **Show Live Code Editing**:
   - Modify the code in the editor (e.g. change `42` to `100` or add `let y = 50`).
   - Notice the amber modified dot `●` appears on the tab.
   - Click `▶ Run` and verify the output updates instantly.
4. **Show Error Handling**:
   - Delete a closing brace `}` and click `▶ Run`.
   - Show that the IDE doesn't crash: the status bar turns red and the `2. Parser` tab automatically activates showing the syntax error.
5. **Show Multilingual Fusion**:
   - Select `Multilingual Fusion` → `comp_1.vital` (which mixes Hindi, Telugu, and English in a single program) and click `▶ Run`.
   - Explain how VITAL's unified lexical and parsing rules seamlessly support multi-script programs.
