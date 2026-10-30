import json
import re
import sys
import contextlib
import os
import ast 
import traceback

# --- CONTRIBUTION 1: Import the real lexer module ---
from lexer import VitalLexer, Token, TokenType

# --- CONFIGURATIONS & CONSTANTS ---
RULES_FILE = 'language_rules.json'
OUTPUT_FILE = 'output.txt'
IR_FILE = 'ir.txt'
LEXER_FILE = 'lexer_log.txt'
PARSER_FILE = 'parser_log.txt'

class Compiler:
    def __init__(self, rules_file):
        self.rules_file = rules_file
        self.translation_map = {}
        # Reverse map: source-language word → TOKEN_* name
        self.keyword_to_token_name = {}
        # Core: Initializing the syntax mapping for Standard IR
        self.syntax = self.get_syntax()
        # CONTRIBUTION 1: Real lexer instance (created after load_rules)
        self.lexer = None
        # CONTRIBUTION 1: Last token stream produced by the lexer
        self.last_token_stream = None
        
    def get_syntax(self):
        """Maps System Tokens to Standard IR (Python) keywords/operators"""
        return {
            "TOKEN_FUNCTION": "def", "TOKEN_RETURN": "return",
            "TOKEN_PRINT": "print", "TOKEN_INPUT": "input",
            "TOKEN_IF": "if", "TOKEN_ELIF": "elif", "TOKEN_ELSE": "else",
            "TOKEN_LOOP_WHILE": "while", "TOKEN_LOOP_FOR": "for",
            "TOKEN_BREAK": "break", "TOKEN_CONTINUE": "continue",
            "TOKEN_EQ_CHECK": "==", "TOKEN_GT": ">", "TOKEN_LT": "<",
            "TOKEN_GTE": ">=", "TOKEN_LTE": "<=", "TOKEN_NEQ": "!=",
            "TOKEN_AND": "and", "TOKEN_OR": "or", "TOKEN_NOT": "not",
            "TOKEN_PLUS": "+", "TOKEN_MINUS": "-", "TOKEN_MULTIPLY": "*",
            "TOKEN_DIVIDE": "/", "TOKEN_ASSIGN": "=", "TOKEN_VAR_DECLARE": "" 
        }

    def load_rules(self):
        """Architecture: Loading the Decoupled Rule-Based JSON Dictionary"""
        base_path = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(base_path, self.rules_file)

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except FileNotFoundError:
            print(f"Rules file not found.")
            sys.exit(1)

        for category, tokens in data.items():
            if category == "IGNORED_TOKENS":
                for token_name, words in tokens.items():
                    # NLP Layer: Stop words map to empty strings to sanitize IR
                    val = "" if token_name == "STOP_WORDS" else "#"
                    for word in words:
                        self.translation_map[word] = val
                        self.keyword_to_token_name[word] = token_name
                continue

            for token_name, synonyms in tokens.items():
                if token_name in self.syntax:
                    py_val = self.syntax[token_name]
                    for word in synonyms:
                        self.translation_map[word] = py_val
                        self.keyword_to_token_name[word] = token_name

        # CONTRIBUTION 1: Instantiate the real lexer with the loaded maps
        self.lexer = VitalLexer(
            self.translation_map,
            self.syntax,
            self.keyword_to_token_name,
        )

    def run_lexer(self, source_code):
        """Frontend: Lexical Analysis - Tokenizing Multilingual Input Stream
        
        CONTRIBUTION 1: Now produces a real structured token stream via the
        VitalLexer, and writes an enhanced lexer log.  The token stream is
        stored in self.last_token_stream for consumption by later stages.
        """
        current_src_dir = os.path.dirname(os.path.abspath(__file__))
        # PATH FIX: Go up one level to root, then into tests
        output_dir = os.path.join(os.path.dirname(current_src_dir), 'tests') 
        if not os.path.exists(output_dir): os.makedirs(output_dir)
        log_path = os.path.join(output_dir, LEXER_FILE)

        # CONTRIBUTION 1: Produce the structured token stream
        self.last_token_stream = self.lexer.tokenize(source_code)

        # CONTRIBUTION 1: Write enhanced lexer log using the real token stream
        self.lexer.write_log(self.last_token_stream, log_path)
        
        print(f"> Lexer Log saved: {LEXER_FILE}")

    def generate_ast_tree(self, node, indent="", is_last=True, file_obj=None):
        """Middle-end: Recursive Abstract Syntax Tree (AST) Visualization"""
        prefix = "└── " if is_last else "├── "
        node_name = type(node).__name__
        
        if isinstance(node, ast.Name):
            node_name += f" (id='{node.id}')"
        elif isinstance(node, ast.Constant):
            node_name += f" (value={repr(node.value)})"
        
        if file_obj:
            file_obj.write(indent + prefix + node_name + "\n")
        
        children = list(ast.iter_child_nodes(node))
        
        for i, child in enumerate(children):
            is_last_child = (i == len(children) - 1)
            new_indent = indent + ("    " if is_last else "│   ")
            self.generate_ast_tree(child, new_indent, is_last_child, file_obj)

    def run_parser(self, source_code):
        """Frontend: Syntax Validation & Structural Integrity Check"""
        current_src_dir = os.path.dirname(os.path.abspath(__file__))
        output_dir = os.path.join(os.path.dirname(current_src_dir), 'tests') 
        log_path = os.path.join(output_dir, PARSER_FILE)
        
        # CONTRIBUTION 1: Consume structured token stream for syntax validation
        self.run_lexer(source_code)
        tokens = self.last_token_stream

        with open(log_path, "w", encoding="utf-8") as f:
            f.write("--- PARSER VALIDATION REPORT ---\n\n")

            # 1. Grammar-aware Delimiter Scope Check via Token Stream LIFO Stack
            open_braces = sum(1 for t in tokens if t.type == TokenType.DELIMITER and t.lexeme == '{')
            close_braces = sum(1 for t in tokens if t.type == TokenType.DELIMITER and t.lexeme == '}')
            open_parens = sum(1 for t in tokens if t.type == TokenType.DELIMITER and t.lexeme == '(')
            close_parens = sum(1 for t in tokens if t.type == TokenType.DELIMITER and t.lexeme == ')')
            open_brackets = sum(1 for t in tokens if t.type == TokenType.DELIMITER and t.lexeme == '[')
            close_brackets = sum(1 for t in tokens if t.type == TokenType.DELIMITER and t.lexeme == ']')

            DELIM_PAIRS = {')': '(', '}': '{', ']': '['}
            OPEN_DELIMS = {'{', '(', '['}
            CLOSE_DELIMS = {'}', ')', ']'}

            stack = []
            unmatched_close = []
            mismatches = []

            for t in tokens:
                if t.type == TokenType.DELIMITER:
                    if t.lexeme in OPEN_DELIMS:
                        stack.append(t)
                    elif t.lexeme in CLOSE_DELIMS:
                        expected_open = DELIM_PAIRS[t.lexeme]
                        if not stack:
                            unmatched_close.append((t, f"Unexpected closing delimiter '{t.lexeme}'"))
                        elif stack[-1].lexeme != expected_open:
                            top = stack.pop()
                            mismatches.append((t, top, f"Mismatched delimiter: opened '{top.lexeme}' at line {top.line}:{top.column} but closed with '{t.lexeme}' at line {t.line}:{t.column}"))
                        else:
                            stack.pop()

            unclosed = stack
            has_delimiter_error = False

            if unmatched_close or mismatches or unclosed:
                has_delimiter_error = True

                # Report extra closing delimiters
                for t, msg in unmatched_close:
                    if t.lexeme == '}':
                        f.write(f"[ERROR] Unbalanced brackets at line {t.line}:{t.column}: Unexpected closing brace '}}'\n")
                    elif t.lexeme == ')':
                        f.write(f"[ERROR] Unbalanced parentheses at line {t.line}:{t.column}: Unexpected closing parenthesis ')'\n")
                    else:
                        f.write(f"[ERROR] Unbalanced delimiters at line {t.line}:{t.column}: {msg}\n")

                # Report mismatched delimiters
                for t, top, msg in mismatches:
                    f.write(f"[ERROR] Delimiter mismatch at line {t.line}:{t.column}: {msg}\n")

                # Report unclosed opening delimiters
                for t in unclosed:
                    if t.lexeme == '{':
                        f.write(f"[ERROR] Unbalanced brackets at line {t.line}:{t.column}: Unclosed '{{' delimiter opened at line {t.line}\n")
                    elif t.lexeme == '(':
                        f.write(f"[ERROR] Unbalanced parentheses at line {t.line}:{t.column}: Unclosed '(' delimiter opened at line {t.line}\n")
                    else:
                        f.write(f"[ERROR] Unbalanced delimiters at line {t.line}:{t.column}: Unclosed '{t.lexeme}' delimiter opened at line {t.line}\n")

                f.write(f"Found {open_braces} '{{' and {close_braces} '}}' delimiter tokens.\n")
                if open_parens != close_parens:
                    f.write(f"Found {open_parens} '(' and {close_parens} ')' delimiter tokens.\n")

            if has_delimiter_error:
                print(f"> Parser Failed. Check {PARSER_FILE}")
                return False

            temp_code = self.transpile(source_code)
            try:
                tree = ast.parse(temp_code) 
                
                ast_path = os.path.join(output_dir, "ast_log.txt")
                with open(ast_path, "w", encoding="utf-8") as ast_file:
                    ast_file.write("--- ABSTRACT SYNTAX TREE (VISUAL) ---\n\n")
                    ast_file.write("Module (Root)\n") 
                    
                    children = list(ast.iter_child_nodes(tree))
                    for i, child in enumerate(children):
                        is_last = (i == len(children) - 1)
                        self.generate_ast_tree(child, "", is_last, ast_file)
                        
                print(f"> Visual AST Log saved: ast_log.txt")

                # CONTRIBUTION 1: Token stream validation report
                non_eof_tokens = [t for t in tokens if t.type != TokenType.EOF]
                keyword_count = sum(1 for t in non_eof_tokens if t.type == TokenType.KEYWORD)
                op_count = sum(1 for t in non_eof_tokens if t.type == TokenType.OPERATOR)
                ident_count = sum(1 for t in non_eof_tokens if t.type == TokenType.IDENTIFIER)
                delim_count = sum(1 for t in non_eof_tokens if t.type == TokenType.DELIMITER)
                lit_count = sum(1 for t in non_eof_tokens if t.type in (TokenType.NUMBER, TokenType.STRING))

                f.write(f"[INFO] Token stream consumed: {len(non_eof_tokens)} active tokens validated.\n")
                f.write(f"[INFO] Token Breakdown: Keywords={keyword_count}, Operators={op_count}, "
                        f"Identifiers={ident_count}, Literals={lit_count}, Delimiters={delim_count}\n")

                f.write("[SUCCESS] Structure is Valid.\n")
                f.write("[SUCCESS] Logic Tree Verified.\n")
            except SyntaxError as e:
                # Capture Syntax Errors in the IR for Debugging/Dashboard
                f.write(f"[ERROR] Logic Error: {e.msg} at line {e.lineno}\n")
                print(f"> Parser Failed. Check {PARSER_FILE}")
                return False

        print(f"> Parser Log saved: {PARSER_FILE}")
        return True

    def security_homoglyph_check(self, source_code):
        """Security Layer: Prevention of Multilingual Homograph Attacks"""
        homoglyphs = {
            # Cyrillic fakes attacking English variables
            'а': 'a', 'е': 'e', 'о': 'o', 'с': 'c', 'р': 'p', 'х': 'x',
            
            # Devanagari fakes attacking syntax and logic
            'ः': ':',   # Devanagari Visarga pretending to be a Colon
            '।': '|',   # Devanagari Danda pretending to be a Pipe
            '०': 'o',   # Devanagari Zero pretending to be lowercase 'o'
            'ऽ': 'S'    # Devanagari Avagraha pretending to be a capital 'S'
        }
        
        safe_code = source_code
        for danger_char, safe_char in homoglyphs.items():
            if danger_char in safe_code:
                try:
                    print(f"> [SECURITY WARNING] Multi-lingual Homoglyph {repr(danger_char)} detected! Normalizing to '{safe_char}'.")
                except Exception:
                    pass
                safe_code = safe_code.replace(danger_char, safe_char)
        return safe_code

    def transpile(self, source_code):
        """Middle-end: IR Design & Generation using Regex Lookarounds"""
        code = self.security_homoglyph_check(source_code)
        
        # Resolve ambiguity by sorting keys by length (Descending)
        sorted_keys = sorted(self.translation_map.keys(), key=len, reverse=True)
        # CONTRIBUTION 2: Added \u0980-\u09FF for Bengali Block Support
        word_char = r'[a-zA-Z0-9_\u0900-\u097F\u0980-\u09FF\u0C00-\u0C7F]'
        
        for key in sorted_keys:
            py_val = self.translation_map[key]
            
            # Boundary Lookarounds to ensure whole-word replacement
            lookbehind = r'(?<!' + word_char + r')'
            lookahead = r'(?!' + word_char + r')'
            
            if py_val == "":
                pattern = re.compile(lookbehind + re.escape(key) + lookahead + r'[ \t]?')
            else:
                pattern = re.compile(lookbehind + re.escape(key) + lookahead)
                
            code = pattern.sub(py_val, code)
            
        # Standard IR Normalization
        # Clean lines starting with '}' (e.g. '} else', '} elif', '}') to preserve Python indentation
        code = re.sub(r'(^[ \t]*)\}[ \t]*', r'\1', code, flags=re.MULTILINE)
        code = code.replace("{", ":").replace("}", "").replace(";", "")
        return code

    def execute(self, code):
        """Backend: Execution Engine & Semantic Symbol Table Mapping"""
        current_src_dir = os.path.dirname(os.path.abspath(__file__))
        output_dir = os.path.join(os.path.dirname(current_src_dir), 'tests') 
        
        final_out = os.path.join(output_dir, OUTPUT_FILE)
        ir_out = os.path.join(output_dir, IR_FILE)

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Standard IR Persistence
        try:
            with open(ir_out, "w", encoding="utf-8") as f:
                f.write(code)
            print(f"> IR generated: {IR_FILE}")
        except Exception as e:
            print(f"Error saving IR: {e}")

        # Isolated Execution Sandbox
        try:
            with open(final_out, "w", encoding="utf-8") as f:
                with contextlib.redirect_stdout(f):
                    # Capture variable states for Semantic Analysis
                    exec_scope = {"__builtins__": __builtins__}
                    exec(code, exec_scope, exec_scope)
                    
                    # Generate Symbol Table (Semantics)
                    symbol_table_path = os.path.join(output_dir, "symbol_table.txt")
                    with open(symbol_table_path, "w", encoding="utf-8") as sym_file:
                        sym_file.write("--- SYMBOL TABLE (SEMANTICS) ---\n")
                        sym_file.write("Variable Name\t| Type\t| Current Value\n")
                        sym_file.write("-" * 50 + "\n")
                        for var_name, var_value in exec_scope.items():
                            if var_name.startswith("__"):
                                continue
                            sym_file.write(f"{var_name}\t| {type(var_value).__name__}\t| {var_value}\n")
                    
            print(f"> Output saved: {OUTPUT_FILE}")
        except Exception as e:
            print(f"> [RUNTIME CRASH] Execution Engine fault.")
            with open(final_out, "w", encoding="utf-8") as f:
                f.write(f"--- RUNTIME ERROR ---\n")
                f.write(f"Execution Error: {e}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <filename>")
    else:
        app = Compiler(RULES_FILE)
        app.load_rules()
        
        fname = sys.argv[1]
        try:
            base_path = os.path.dirname(os.path.abspath(__file__))
            file_path = os.path.join(base_path, fname)
            
            with open(file_path, 'r', encoding='utf-8') as f:
                src = f.read()
            
            app.run_lexer(src)
            is_valid = app.run_parser(src)
            
            if is_valid:
                py_code = app.transpile(src)
                app.execute(py_code)
            else:
                print("Compilation stopped due to errors.")
            
        except FileNotFoundError:
            print(f"File not found.")