# 🔬 Complete Project Analysis: Multilingual Programming Language Compiler

---

## 1. What This Project Is Supposed To Do (Simple Terms)

This project is a **transpiler** (source-to-source compiler) for a custom language called **Vital** (`.vital` files). It lets users write programs using keywords in **English, Hindi (Devanagari), and Telugu** — and they can even mix all three in the same file. Under the hood, every Vital keyword is **translated into the equivalent Python keyword**, the curly-brace syntax is converted to Python's indentation-based syntax, and the resulting Python code is directly **executed** using Python's `exec()`.

**In one sentence**: You write code in Hindi/Telugu/English → it gets translated to Python → Python runs it.

> [!IMPORTANT]
> This is a **transpiler**, not a traditional compiler. It does NOT produce machine code or bytecode of its own. It translates Vital → Python and then delegates execution to the Python runtime.

---

## 2. Languages, Frameworks, and Tools Used

| Category | Technology | Purpose |
|---|---|---|
| **Language** | Python 3 | Everything is written in Python |
| **Standard Library** | `re`, `json`, `ast`, `sys`, `os`, `contextlib` | Regex, JSON parsing, AST introspection, execution sandboxing |
| **GUI** | `tkinter` (built-in) | Desktop IDE for writing and running `.vital` programs |
| **Benchmarking** | `codecarbon`, `matplotlib`, `pandas`, `numpy` | Energy measurement, speed profiling, graphing |
| **Rule Store** | `language_rules.json` | Keyword dictionary mapping multilingual words to system tokens |
| **File Format** | `.vital` | Custom source code file extension |

---

## 3. Complete Execution Flow: `.vital` → Output

```
┌─────────────────────────────────────┐
│  User writes .vital source code     │
│  (Hindi / Telugu / English mix)     │
└──────────────┬──────────────────────┘
               │  raw string (source code)
               ▼
┌─────────────────────────────────────┐
│  load_rules()                       │
│  Builds translation_map from JSON   │
│  (one-time setup)                   │
└──────────────┬──────────────────────┘
               │  translation_map dict ready
               ▼
┌─────────────────────────────────────┐
│  run_lexer(source_code)             │  ← LOGGING ONLY
│  Classifies each word/symbol into   │
│  KEYWORD / ID / NUM / SYM           │
│  Writes → lexer_log.txt             │
└──────────────┬──────────────────────┘
               │  raw source code (UNCHANGED, passed through)
               ▼
┌─────────────────────────────────────┐
│  run_parser(source_code)            │
│  1. Checks brace balance            │
│  2. Calls transpile() internally    │
│  3. Feeds result to ast.parse()     │
│  4. Generates visual AST tree       │
│  Writes → parser_log.txt            │
│  Writes → ast_log.txt               │
│  Returns True/False                 │
└──────────────┬──────────────────────┘
               │  boolean (is_valid) + raw source code still available
               ▼
┌─────────────────────────────────────┐
│  transpile(source_code)             │  ← CALLED AGAIN (2nd time)
│  1. Homoglyph security check        │
│  2. Regex word-by-word replacement   │
│  3. { → : , } → "", ; → ""          │
│  Produces valid Python code string   │
└──────────────┬──────────────────────┘
               │  Python code string (the "IR")
               ▼
┌─────────────────────────────────────┐
│  execute(py_code)                   │
│  1. Saves IR → ir.txt               │
│  2. exec(py_code) in sandbox        │
│  3. Captures stdout → output.txt    │
│  4. Dumps local_memory →            │
│     symbol_table.txt                │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Output files in tests/ directory:  │
│  • output.txt     (program output)  │
│  • ir.txt         (Python code)     │
│  • lexer_log.txt  (token list)      │
│  • parser_log.txt (validation)      │
│  • ast_log.txt    (tree visual)     │
│  • symbol_table.txt (variables)     │
└─────────────────────────────────────┘
```

> [!WARNING]
> **`transpile()` is called TWICE** in a normal run — once inside `run_parser()` (line 140 of [main.py](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/main.py#L140)) and once again in the main flow (line 276). This is a redundancy, not intentional design.

---

## 4. Important Files and Their Purpose

### Core Source Files

| File | Purpose |
|---|---|
| [`main.py`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/main.py) | **The entire compiler in one file.** Contains the `Compiler` class with lexer, parser, transpiler, executor, and entry point. |
| [`language_rules.json`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/language_rules.json) | **Keyword dictionary.** Maps multilingual synonyms to internal token names. This is the "grammar definition" for keywords. |
| [`gui.py`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/gui.py) | **Tkinter desktop IDE.** Editor + console that calls the same `Compiler` class from main.py. |
| [`benchmark.py`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/benchmark.py) | **Performance testing.** Measures energy (CodeCarbon), speed (time complexity), and comparative workload profiling. |
| [`demo.vital`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/demo.vital) | A sample Telugu program (multiplication table with skip logic). |

### Test Program Directories

| Directory | Description | # Files |
|---|---|---|
| [`low/`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/low) | Low complexity programs (grading, leap year, etc.) | 5 |
| [`med/`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/med) | Medium complexity (Collatz, algorithms) | 5 |
| [`high/`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/high) | High complexity (factorial stress, Fibonacci) | 5 |
| [`complex/`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/complex) | Complex programs (digit reversal, multilingual mixing) | 5 |

### Output Directories

| Directory | Contents |
|---|---|
| `tests/` (project root level) | Log files from benchmark runs (large lexer/AST logs from the speed benchmark's 1000-line synthetic input) |
| `src/tests/` | Log files from the most recent GUI/direct invocation run |

---

## 5. `main.py` and the Main Entry Point

[`main.py`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/main.py) contains **everything** — it is a single `Compiler` class plus a `__main__` guard.

### Entry Point ([lines 257–282](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/main.py#L257-L282))

```python
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <filename>")
    else:
        app = Compiler(RULES_FILE)
        app.load_rules()
        
        fname = sys.argv[1]
        # ... reads the file ...
        
        app.run_lexer(src)
        is_valid = app.run_parser(src)
        
        if is_valid:
            py_code = app.transpile(src)
            app.execute(py_code)
        else:
            print("Compilation stopped due to errors.")
```

**Usage**: `python main.py demo.vital`

The `Compiler` class has these methods:

| Method | Role |
|---|---|
| `__init__` / `get_syntax()` | Initializes the token-to-Python mapping |
| `load_rules()` | Loads `language_rules.json`, builds `translation_map` |
| `run_lexer()` | Tokenizes input, writes log (does NOT return tokens) |
| `run_parser()` | Validates structure via `ast.parse()`, writes AST log |
| `security_homoglyph_check()` | Replaces lookalike Unicode characters |
| `transpile()` | The core: translates Vital → Python via regex |
| `execute()` | Runs the Python string via `exec()`, captures output |
| `generate_ast_tree()` | Recursive helper to pretty-print Python's AST |

---

## 6. The Lexer

### Where Implemented
[`Compiler.run_lexer()`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/main.py#L65-L99) — lines 65–99 of main.py.

### Input
A raw **string** of the entire `.vital` source code.

### Output
The lexer **does NOT return tokens to the pipeline**. It only writes a human-readable log to `lexer_log.txt`. The lexer is purely a **diagnostic/logging** tool.

### What Tokens/Keywords It Recognizes

It classifies each word into exactly one of four categories:

| Token Type | Detection Method | Example |
|---|---|---|
| `KEYWORD(...)` | Word found in `translation_map` | `KEYWORD(=)`, `KEYWORD(print)`, `KEYWORD()` (empty = stop word or `let`) |
| `NUM(...)` | Matches `^\d+$` | `NUM(150)`, `NUM(7)` |
| `ID(...)` | Matches `^[a-zA-Z_\u0900-\u097F\u0C00-\u0C7F][\w\u0900-\u097F\u0C00-\u0C7F]*$` | `ID(యూనిట్లు)`, `ID(अंक)` |
| `SYM(...)` | Everything else (single non-word characters) | `SYM(()`, `SYM(})`, `SYM(")` |

The word-splitting regex (`line 83`) is:
```python
re.findall(r"[a-zA-Z0-9_\u0900-\u097F\u0C00-\u0C7F]+|[^\s\w]", line)
```
- The `\u0900-\u097F` range covers **Devanagari** (Hindi)
- The `\u0C00-\u0C7F` range covers **Telugu**

### Example Lexer Output
For the line `అనుకో యూనిట్లు = 150`:
```
Line 4: ['KEYWORD()', 'ID(యూనిట్లు)', 'KEYWORD(=)', 'NUM(150)']
```
Note: `KEYWORD()` is **empty** because `అనుకో` maps to `TOKEN_VAR_DECLARE`, which maps to `""` (empty string) in `get_syntax()`.

> [!NOTE]
> The lexer and the transpiler are **completely independent**. The transpiler does not consume lexer tokens. The lexer is a side-effect-only logging pass.

---

## 7. The Parser

### Where Implemented
[`Compiler.run_parser()`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/main.py#L121-L165) — lines 121–165 of main.py.

### What It Receives
The **raw source code string** (same string the lexer got — NOT tokens).

### What It Does (Step by Step)
1. **Brace balance check**: Counts `{` vs `}` — if they mismatch, it reports an error immediately.
2. **Calls `self.transpile(source_code)`** internally to translate Vital → Python.
3. **Calls `ast.parse(temp_code)`** — this is Python's built-in AST parser. If the transpiled code is not valid Python, a `SyntaxError` is raised.
4. **Generates a visual AST** by recursively walking the Python AST tree and writing a pretty-printed tree to `ast_log.txt`.
5. Returns `True` (valid) or `False` (error).

### What It Produces
- `parser_log.txt`: SUCCESS or ERROR messages
- `ast_log.txt`: A visual tree representation of the Python AST
- A **boolean** return value (`True`/`False`)

### Is There a Custom Grammar?
**No.** There is no grammar specification (no BNF, no EBNF, no context-free grammar rules, no recursive descent parser, no parser generator like ANTLR/Yacc/Lark). The "parser" delegates entirely to Python's `ast.parse()`. The Vital language's grammar is implicitly the Python grammar with word substitution.

> [!IMPORTANT]
> The "parser" in this project is **not a parser in the compiler-theory sense**. It is a validation step that checks whether the transpiled Python code is syntactically valid by letting Python itself parse it.

---

## 8. The AST

### Is There a Custom AST?
**No.** The project uses **Python's built-in `ast` module** (`import ast`). After transpiling Vital code to Python, it calls `ast.parse()` which returns a standard CPython AST.

### What Gets Logged
The method [`generate_ast_tree()`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/main.py#L101-L119) recursively walks this Python AST and writes a tree visualization:

```
Module (Root)
├── Assign
│   ├── Name (id='units')
│   │   └── Store
│   └── Constant (value=150)
├── If
│   ├── Compare
│   │   ├── Name (id='units')
│   │   │   └── Load
│   │   ├── Gt
│   │   └── Constant (value=100)
│   ├── Expr
│   │   └── Call
│   │       ├── Name (id='print')
│   │       │   └── Load
│   │       └── Constant (value='Discount Applied!')
```

**This AST is used only for visualization/logging** — it is never consumed by any later stage.

---

## 9. The Symbol Table

### Where Implemented
Inside [`Compiler.execute()`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/main.py#L237-L248) — lines 237–248 of main.py.

### What Information It Stores

| Column | Description |
|---|---|
| Variable Name | The identifier (after translation to Python) |
| Type | Python type name (`int`, `float`, `str`, `function`) |
| Current Value | The value after execution completes |

### When It Is Created/Updated
**After** `exec()` finishes running the program. The `local_memory` dictionary is the second argument to `exec()` — Python populates it with all variables created during execution. The code then dumps this dictionary to `symbol_table.txt`.

```python
local_memory = {}
exec(code, {"__builtins__": __builtins__}, local_memory)

# After exec, local_memory contains all variables
for var_name, var_value in local_memory.items():
    sym_file.write(f"{var_name}\t| {type(var_value).__name__}\t| {var_value}\n")
```

### Example Output
```
--- SYMBOL TABLE (SEMANTICS) ---
Variable Name	| Type	| Current Value
--------------------------------------------------
units	| int	| 150
charge	| int	| 50
rate	| int	| 5
total	| int	| 800
discount	| float	| 80.0
final_bill	| float	| 720.0
```

> [!NOTE]
> This is **not** a symbol table in the traditional compiler sense (which tracks scope, type information, declaration points, etc. *during* compilation). This is a **post-execution memory dump** of Python's locals dictionary. It only captures the final state of variables after the entire program finishes.

---

## 10. The Transpiler / Code Generator

### Where Implemented
[`Compiler.transpile()`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/main.py#L187-L212) — lines 187–212 of main.py.

### What Representation It Receives
The **raw source code string** from the `.vital` file.

### What It Generates
A **valid Python code string**. This is the heart of the entire system.

### How It Works (Step by Step)

**Step 1: Security Homoglyph Check** ([line 189](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/main.py#L189))
Replaces lookalike characters (e.g., Cyrillic `а` → Latin `a`).

**Step 2: Sort Translation Keys** ([line 192](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/main.py#L192))
Keys are sorted by length (longest first) to prevent shorter keys from replacing substrings of longer keys. For example, `या` (or) won't corrupt `या_अगर` (elif).

**Step 3: Regex Word-Boundary Replacement** ([lines 196–208](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/main.py#L196-L208))
For each keyword in `translation_map`, a regex with **lookaround assertions** is used:
```python
lookbehind = r'(?<!' + word_char + r')'   # NOT preceded by a word char
lookahead = r'(?!' + word_char + r')'     # NOT followed by a word char
pattern = re.compile(lookbehind + re.escape(key) + lookahead)
code = pattern.sub(py_val, code)
```
Stop words (like `तो`, `को`, `is`, `please`) map to `""` and are silently deleted, consuming any trailing whitespace.

**Step 4: Syntax Normalization** ([line 211](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/main.py#L211))
```python
code = code.replace("{", ":").replace("}", "").replace(";", "")
```
Curly braces become Python colons. Closing braces and semicolons are stripped.

### Where Execution Happens
In [`Compiler.execute()`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/main.py#L214-L256), the transpiled Python string is executed via `exec()`:
```python
exec(code, {"__builtins__": __builtins__}, local_memory)
```
Stdout is redirected to `output.txt` using `contextlib.redirect_stdout`.

---

## 11. IR / Intermediate Representation and Logs

### The "IR"
The project calls the transpiled Python code the "IR" (Intermediate Representation). It is saved to `ir.txt` by the [`execute()`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/main.py#L226-L231) method.

> [!WARNING]
> In traditional compiler terminology, the "IR" is an abstract, platform-independent representation (like three-address code, SSA, or LLVM IR). Here, the "IR" is **just valid Python source code**. It is human-readable and directly executable. There is no separate IR in the academic sense.

### Example: Vital Code → "IR" (Python)

**Input** (from [low_2.vital](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/low/low_2.vital)):
```
let year = 2024
let is_leap = 0
if (year % 400 == 0) {
    let is_leap = 1
}
```

**Transpiled "IR"**:
```python
year = 2024
is_leap = 0
if (year % 400 == 0) :
    is_leap = 1
```

### All Log Files Produced

| Log File | Created By | Contents |
|---|---|---|
| `lexer_log.txt` | `run_lexer()` | Token classification per line |
| `parser_log.txt` | `run_parser()` | SUCCESS/ERROR validation result |
| `ast_log.txt` | `run_parser()` → `generate_ast_tree()` | Pretty-printed Python AST |
| `ir.txt` | `execute()` | The transpiled Python code |
| `symbol_table.txt` | `execute()` | Post-execution variable dump |
| `output.txt` | `execute()` | Captured stdout of the program |

---

## 12. The GUI and How It Connects to the Compiler

### Where Implemented
[`gui.py`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/gui.py) — 172 lines of Tkinter code.

### Layout
The GUI is a **split-pane** desktop application:

```
┌──────────────────────────────────────────────────┐
│  Multilingual Programming Language Compiler       │
├───────────────────────┬──────────────────────────┤
│                       │                          │
│  Source Code (.vital) │  Architecture Pipeline   │
│                       │  Logs                    │
│  [Editor panel with   │                          │
│   scrollable text     │  Shows all log files:    │
│   area]               │  • Execution Output      │
│                       │  • Lexer Analysis        │
│                       │  • Parser Validation     │
│                       │  • AST                   │
│                       │  • Transpiled IR         │
│                       │  • Symbol Table          │
│                       │                          │
├───────────┬───────────┤                          │
│📂 LOAD    │▶ COMPILE  │                          │
│ .VITAL    │ & RUN     │                          │
│ FILE      │           │                          │
├───────────┴───────────┴──────────────────────────┤
│ Status: System Ready | Multilingual Engine Loaded │
└──────────────────────────────────────────────────┘
```

### How It Connects
The GUI imports the `Compiler` class directly:
```python
from main import Compiler, RULES_FILE
```

The [`run_compiler()`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/gui.py#L29-L101) function:
1. Reads source code from the editor text widget
2. Creates a `Compiler` instance, calls `load_rules()`
3. Calls `run_lexer()`, `run_parser()`, `transpile()`, `execute()` — the exact same flow as `main.py`
4. Reads all 6 log files from disk and displays them in the console panel

The `LOAD .VITAL FILE` button uses `filedialog.askopenfilename()` to load a `.vital` file into the editor.

### Color Theme
"Oceanic Slate" dark theme: deep navy background (`#0F172A`), sky blue accents (`#38BDF8`), warm amber headers (`#FBBF24`), rose red errors (`#F43F5E`), soft purple log text (`#A78BFA`).

---

## 13. The Benchmark Module

### Where Implemented
[`benchmark.py`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/benchmark.py) — 231 lines.

### Three Benchmark Modes

#### Mode 1: Single File Energy Visualization ([`run_energy_benchmark()`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/benchmark.py#L13-L70))
- Opens a **file picker** to select a `.vital` file
- Runs the **entire compilation pipeline 100 times** in a loop
- Uses **CodeCarbon** (`EmissionsTracker`) to measure CPU energy (via Intel RAPL) and RAM energy
- Produces a **bar chart** comparing CPU vs RAM energy in mWh

#### Mode 2: Time Complexity ([`run_speed_benchmark()`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/benchmark.py#L72-L108))
- Generates **synthetic** Vital code of varying sizes (10, 50, 100, 500, 1000, 2000 lines)
- The synthetic code is `मानो चर = 1\nఅనుకో చరరాశి = 2\n` repeated
- Measures total compilation + execution time per size
- Produces a **line graph** (Lines of Code vs. Execution Time in ms)

#### Mode 3: Comparative Workload Profile ([`run_comparative_benchmark()`](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/benchmark.py#L110-L209))
- Scans the `low/`, `med/`, `high/`, `complex/` subdirectories
- Runs each `.vital` file 10 times (then multiplies results by 10 to simulate 100 runs)
- Uses `OfflineEmissionsTracker` (no internet needed)
- Produces a **dual bar chart**: energy (mWh) and speed (ms) for all 20 files, color-coded by difficulty

> [!NOTE]
> The benchmark runs contain a **10x multiplier hack** on line 171–172 of benchmark.py:
> ```python
> total_time_ms = ((end_time - start_time) * 1000) * 10
> energy_mWh = (tracker._total_energy.kWh * 1000) * 10
> ```
> This artificially inflates the numbers so graphs "match the 100-loop scale" while only running 10 iterations for speed during screen recordings.

---

## 14. Example Program Traces

### Example 1: Simple Hindi Program — [low_1.vital](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/low/low_1.vital)

**Source Code:**
```
टिप्पणी Complex University Grading System
मानो अंक = 88
मानो उपस्थिति = 95

लिखो("--- Student Academic Report ---")
लिखो("Total Marks:")
लिखो(अंक)

अगर (अंक >= 90) {
    लिखो("Grade: O (Outstanding)")
}
या_अगर (अंक >= 80 तथा उपस्थिति >= 90) {
    लिखो("Grade: A+ (Excellent with Bonus)")
}
```

#### Step-by-step trace:

**① `load_rules()`** reads `language_rules.json` and builds `translation_map`:
```
{
  "टिप्पणी": "#",       ← COMMENTS token
  "मानो": "",           ← TOKEN_VAR_DECLARE → empty string
  "लिखो": "print",     ← TOKEN_PRINT
  "अगर": "if",         ← TOKEN_IF
  "या_अगर": "elif",   ← TOKEN_ELIF
  "अन्यथा": "else",   ← TOKEN_ELSE
  "तथा": "and",        ← TOKEN_AND
  "तो": "",            ← STOP_WORD
  ...
}
```

**② `run_lexer(source_code)`** — Classifies each word on each line:
```
Line 2: ['KEYWORD()', 'ID(अंक)', 'KEYWORD(=)', 'NUM(88)']
Line 5: ['KEYWORD(print)', 'SYM(()', 'SYM(")', 'SYM(-)', 'SYM(-)', 'SYM(-)', ...]
Line 9: ['KEYWORD(if)', 'SYM(()', 'ID(अंक)', 'KEYWORD(>=)', 'NUM(90)', 'SYM())', 'SYM({)']
```
Writes to `lexer_log.txt`. **Does not return anything usable.**

**③ `run_parser(source_code)`** — Checks `{` vs `}` count. Then internally calls `transpile()`, producing:
```python
# Complex University Grading System
अंक = 88
उपस्थिति = 95

print("--- Student Academic Report ---")
print("Total Marks:")
print(अंक)

if (अंक >= 90) :
    print("Grade: O (Outstanding)")

elif (अंक >= 80 and उपस्थिति >= 90) :
    print("Grade: A+ (Excellent with Bonus)")
```
Calls `ast.parse()` on this → succeeds → writes AST tree → returns `True`.

**④ `transpile(source_code)`** (called AGAIN in main flow):
Same output as above. Key transformations:
- `टिप्पणी` → `#` (comment)
- `मानो` → `""` (deleted, leaving `अंक = 88`)
- `लिखो` → `print`
- `अगर` → `if`
- `या_अगर` → `elif`
- `तथा` → `and`
- `{` → `:`, `}` → (deleted)

**⑤ `execute(py_code)`**:
- Saves the Python code to `ir.txt`
- Runs `exec(py_code)` → captures stdout to `output.txt`
- Dumps `local_memory` to `symbol_table.txt`

**Output** (`output.txt`):
```
--- Student Academic Report ---
Total Marks:
88
Grade: A+ (Excellent with Bonus)
```

**Symbol Table** (`symbol_table.txt`):
```
अंक      | int   | 88
उपस्थिति  | int   | 95
```

---

### Example 2: Telugu Program — [demo.vital](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/demo.vital)

**Source Code:**
```
వ్యాఖ్య Multiplication Table with Skip Logic
అనుకో ఎక్కం = 7
అనుకో గుణకం = 0

రాయి("Table of 7 (Skipping 5):")

ఉన్నంతవరకు (గుణకం కంటే_చిన్నది 10) {
    అనుకో గుణకం = గుణకం కలుపు 1
    
    ఒకవేళ (గుణకం సమానం 5) {
        కొనసాగించు
    }
    
    అనుకో ఫలితం = ఎక్కం హెచ్చవేయి గుణకం
    రాయి(ఫలితం)
}
```

**After `transpile()`** → The "IR":
```python
# Multiplication Table with Skip Logic
ఎక్కం = 7
గుణకం = 0

print("Table of 7 (Skipping 5):")

while (గుణకం < 10) :
    గుణకం = గుణకం + 1
    
    if (గుణకం == 5) :
        continue
    
    ఫలితం = ఎక్కం * గుణకం
    print(ఫలితం)
```

Key transformations:
- `వ్యాఖ్య` → `#` (comment)
- `అనుకో` → `""` (deleted, it's `TOKEN_VAR_DECLARE`)
- `రాయి` → `print`
- `ఉన్నంతవరకు` → `while`
- `కంటే_చిన్నది` → `<`
- `కలుపు` → `+`
- `ఒకవేళ` → `if`
- `సమానం` → `==`
- `కొనసాగించు` → `continue`
- `హెచ్చవేయి` → `*`

**Output**: `7, 14, 21, 28, 42, 49, 56, 63, 70` (skipping `35` because `గుణకం == 5` triggers `continue`).

---

### Example 3: Multilingual Mixed Program — [comp_1.vital](file:///d:/vibeCoding/MULTILINGUAL%20PROGRAMMING%20LANGUAGE%20COMPILER/src/complex/comp_1.vital)

**Source Code** (mixes Hindi + Telugu + English in ONE file):
```
टिप्पणी Number Digit Reversal using Multilingual Math
मानो number = 987654321
అనుకో reversed = 0

लिखो("Reversing large integer...")

ఉన్నంతవరకు (number > 0) {
    let remainder = number % 10
    అనుకో reversed = (reversed * 10) + remainder
    मानो number = number / 10
}
రాయి("Reversal Complete.")
print(reversed)
```

**After `transpile()`**:
```python
# Number Digit Reversal using Multilingual Math
number = 987654321
reversed = 0

print("Reversing large integer...")

while (number > 0) :
    remainder = number % 10
    reversed = (reversed * 10) + remainder
    number = number / 10

print("Reversal Complete.")
print(reversed)
```

Notice how `टिप्पणी` (Hindi comment marker), `మానో` (Hindi `let`), `అనుకో` (Telugu `let`), `let` (English `let`), `లిఖో` (Hindi `print`), `రాయి` (Telugu `print`), and `print` (English `print`) all coexist and all map to the correct Python equivalents.

---

## Distinguishing: Actually Implemented vs. Intended But Not Implemented

### ✅ A. Actually Implemented

| Feature | Status |
|---|---|
| Multilingual keyword translation (Hindi, Telugu, English) | ✅ Working |
| Curly-brace to Python indentation conversion | ✅ Working (via `{` → `:` and `}` → `""`) |
| Stop word removal (fillers like `तो`, `को`, `is`, `please`) | ✅ Working |
| Homoglyph security check | ✅ Working (for a limited set of characters) |
| Lexer token classification (log only) | ✅ Working (but unused by pipeline) |
| Validation via Python's `ast.parse()` | ✅ Working |
| AST visualization using Python's `ast` module | ✅ Working |
| Post-execution symbol table dump | ✅ Working |
| Transpile to Python and `exec()` | ✅ Working |
| Tkinter GUI IDE | ✅ Working |
| Energy + speed benchmarking | ✅ Working (requires CodeCarbon) |

### ⚠️ B. Intended/Implied But Not Actually Implemented

| Feature | Evidence of Intent | Reality |
|---|---|---|
| **Custom lexer that feeds tokens to the parser** | Named `run_lexer()`, categorizes tokens | Tokens are logged and discarded. The parser/transpiler do not consume them. |
| **Custom parser with grammar rules** | Named `run_parser()`, has docstring "Syntax Validation" | Delegates entirely to Python's `ast.parse()`. No custom grammar. |
| **True Intermediate Representation** | File named `ir.txt`, comments mention "Standard IR" | The "IR" is just Python source code, not a formal IR like three-address code. |
| **True symbol table with scope tracking** | File named `symbol_table.txt`, comments mention "Semantics" | It's a post-execution memory dump, not a compile-time symbol table. No scope, no declaration tracking. |
| **Semantic analysis** | Method docstring mentions "Semantic Symbol Table Mapping" | No semantic analysis happens. No type checking, no scope resolution, no use-before-declaration checking. |
| **`TOKEN_START` / `TOKEN_STOP`** (begin/end blocks) | Defined in `language_rules.json` under `PROGRAM_STRUCTURE` | These tokens are loaded into `translation_map` but `TOKEN_START` and `TOKEN_STOP` are **not** in `get_syntax()`, so they are never mapped to anything. They will be left as-is or silently ignored. |
| **`TOKEN_CONST`** (constants) | Defined in `language_rules.json` | Not in `get_syntax()`. `const`, `fixed`, `నియత`, `స్థిరం` are never translated. |
| **Functions / `TOKEN_FUNCTION`** | `"TOKEN_FUNCTION": "def"` exists in syntax | Functions are translated but have not been demonstrated in any test file. |
| **Error recovery** | Parser logs errors | On error, compilation simply stops. No error recovery, no helpful diagnostics pointing to the original Vital source line. |
| **`input()` support** | `TOKEN_INPUT` → `input` mapping exists | Would technically work via `exec()`, but `exec()` runs with stdout redirected, and no test program demonstrates it. Unclear if it would function correctly in the GUI. |

---

## WHAT I NEED TO UNDERSTAND BEFORE TOUCHING THIS PROJECT

Since you know Theory of Computation (regular languages, grammars, automata), here's your learning path — each concept builds on your existing knowledge:

### Phase 1: Connecting ToC to Compilers

| # | Concept | Why You Need It | Connection to What You Know |
|---|---|---|---|
| 1 | **Lexical Analysis (Tokenization)** | The lexer in this project is logging-only. To make it real, you need to understand how a lexer works. | You know regular expressions and finite automata. **A lexer is just a DFA** that reads characters and produces tokens. Each token type (NUMBER, KEYWORD, ID) corresponds to a regular language. The regexes in `run_lexer()` are doing exactly this. |
| 2 | **Token Streams** | The lexer should produce a structured stream that the parser consumes. Right now it doesn't. | Think of it as: the lexer is the function that converts the input string (over the input alphabet Σ) into a stream of tokens (over a new alphabet Γ of token types). |
| 3 | **Context-Free Grammars (CFGs) for Programming Languages** | The Vital language has no formal grammar. To extend it properly, you need one. | You already know CFGs and production rules. A programming language grammar is just a CFG where the terminals are tokens (from the lexer) and the non-terminals are syntactic constructs like `expression`, `statement`, `block`. |
| 4 | **Parsing Algorithms** | The current "parser" is fake (delegates to Python). A real parser builds your own AST from your own grammar. | **Recursive Descent** = each non-terminal in your grammar becomes a function. **LL(1)** = top-down, 1 token lookahead (connects to your knowledge of PDAs and deterministic parsing). These are the easiest to implement by hand. |
| 5 | **Abstract Syntax Trees (ASTs)** | The project uses Python's AST. A real compiler needs its own AST that represents Vital's semantics, not Python's. | An AST is a parse tree with the syntactic sugar removed. Each node type corresponds to a production rule in your CFG, but only the semantically meaningful parts. |

### Phase 2: Semantic Analysis

| # | Concept | Why You Need It |
|---|---|---|
| 6 | **Symbol Tables (real ones)** | Track variable declarations, types, scopes. The current "symbol table" is just a post-mortem dump. A real symbol table is built during compilation and catches errors like "variable used before declaration". |
| 7 | **Scope and Binding** | Variables inside `{...}` blocks should potentially have different scope than outer ones. Currently there's no scope management. |
| 8 | **Type Systems** | Vital has no type system. Understanding static vs. dynamic typing, type inference, and type checking will be essential for any future extension. |

### Phase 3: Code Generation and IR

| # | Concept | Why You Need It |
|---|---|---|
| 9 | **Intermediate Representations** | The current "IR" is Python source code. A real IR (like three-address code or SSA form) is platform-independent and enables optimizations. |
| 10 | **Transpilation vs. Compilation** | Understand the trade-offs. This project transpiles to Python. If you ever want to emit bytecode or machine code, you need to understand target code generation. |
| 11 | **Code Generation** | Walking the AST to produce output code. The current `transpile()` method does text substitution without an AST. A proper code generator walks the AST node by node. |

### Phase 4: Practical Skills

| # | Concept | Why You Need It |
|---|---|---|
| 12 | **Error Handling and Diagnostics** | Currently errors point to the *transpiled Python*, not the original Vital source. Good compilers map errors back to source locations. |
| 13 | **Testing Compilers** | How to write tests that verify your compiler produces correct output for given inputs. Snapshot testing, fuzzing, etc. |

### Recommended Resources (in order)

1. **"Crafting Interpreters" by Robert Nystrom** (free online at craftinginterpreters.com) — Walks you through building a complete language from scratch. Covers exactly concepts 1–11 above in a practical, code-first way.
2. **The "Dragon Book" (Compilers: Principles, Techniques, and Tools)** — The theoretical reference. Chapters 1–6 connect directly to your ToC background. Heavy but authoritative.
3. **"Writing An Interpreter In Go" by Thorsten Ball** — Very practical, builds a working interpreter step by step.
