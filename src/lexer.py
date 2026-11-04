"""
lexer.py — Real Lexical Analysis Module for the VITAL Compiler

CONTRIBUTION 1: Implements a genuine lexical-analysis stage that produces
a structured token stream consumed by the rest of the compiler pipeline.

Each Token carries:
  - type      : TokenType enum value (KEYWORD, IDENTIFIER, NUMBER, etc.)
  - lexeme    : the original source spelling (e.g. "अगर")
  - value     : normalized internal value (e.g. "if")
  - line      : 1-based source line number
  - column    : 1-based column number

The lexer supports all six VITAL languages:
  English, Hindi, Telugu, Bengali, Marathi, Nepali
"""

import re
import os
import json
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import List, Dict, Optional


class LexerError(ValueError):
    """Raised when a lexical error is encountered during tokenization."""
    pass


# ---------------------------------------------------------------------------
# Token Type Enumeration
# ---------------------------------------------------------------------------
class TokenType(Enum):
    """Classifies every lexeme produced by the lexer."""
    KEYWORD     = auto()   # Language keyword (if, print, मानो, etc.)
    IDENTIFIER  = auto()   # User-defined name / variable
    NUMBER      = auto()   # Integer or floating-point literal
    STRING      = auto()   # Quoted string literal
    OPERATOR    = auto()   # Arithmetic / relational / logical operator
    DELIMITER   = auto()   # ( ) { } ; ,
    COMMENT     = auto()   # Single-line comment
    NEWLINE     = auto()   # Logical line terminator
    EOF         = auto()   # End-of-file sentinel


# ---------------------------------------------------------------------------
# Token Data Class
# ---------------------------------------------------------------------------
@dataclass
class Token:
    """
    Immutable representation of a single lexical token.

    Attributes
    ----------
    type : TokenType
        The classification of this token.
    lexeme : str
        The original characters as they appear in source code.
    value : str
        The normalised / internal value.  For keywords this is the
        Python-equivalent keyword (e.g. "if"); for identifiers it is
        the original lexeme; for numbers it is the numeric string.
    line : int
        1-based line number where the token starts.
    column : int
        1-based column number where the token starts.
    token_name : str
        The internal token name (e.g. "TOKEN_IF", "TOKEN_PRINT") for
        keywords, or "" for other token types.
    """
    type: TokenType
    lexeme: str
    value: str
    line: int
    column: int
    token_name: str = ""

    def __repr__(self):
        if self.type in (TokenType.KEYWORD, TokenType.OPERATOR) and self.token_name:
            return f"Token({self.type.name}, lexeme={self.lexeme!r}, value={self.value!r}, token={self.token_name}, L{self.line}:C{self.column})"
        return f"Token({self.type.name}, {self.lexeme!r}, L{self.line}:C{self.column})"


# ---------------------------------------------------------------------------
# Unicode Block Ranges — used for identifier recognition
# ---------------------------------------------------------------------------
# Devanagari (Hindi, Marathi, Nepali): U+0900 – U+097F
# Bengali:                             U+0980 – U+09FF
# Telugu:                              U+0C00 – U+0C7F
_UNICODE_LETTER_RANGES = (
    r'\u0900-\u097F'   # Devanagari
    r'\u0980-\u09FF'   # Bengali
    r'\u0C00-\u0C7F'   # Telugu
)

# A "word character" for the VITAL language: ASCII alphanumerics + underscore
# plus supported Indic script blocks.
_WORD_CHAR = rf'[a-zA-Z0-9_{_UNICODE_LETTER_RANGES}]'
_WORD_START = rf'[a-zA-Z_{_UNICODE_LETTER_RANGES}]'


# ---------------------------------------------------------------------------
# Lexer Class
# ---------------------------------------------------------------------------
class VitalLexer:
    """
    Multilingual lexer for the VITAL programming language.

    Usage
    -----
        lexer = VitalLexer(translation_map, syntax_map)
        tokens = lexer.tokenize(source_code)

    Parameters
    ----------
    translation_map : dict
        Maps every recognised source-language keyword/operator spelling to
        its Python-equivalent string.  Built by ``Compiler.load_rules()``.
    syntax_map : dict
        Maps internal TOKEN_* names to Python keywords/operators.
        Built by ``Compiler.get_syntax()``.
    keyword_to_token_name : dict
        Reverse map: source-language word → TOKEN_* name.
    """

    # Operators that may be one or two characters (order matters: longest first)
    _TWO_CHAR_OPS = {'==', '!=', '>=', '<=', '//'}
    _ONE_CHAR_OPS = {'+', '-', '*', '/', '%', '=', '>', '<', '!'}
    _DELIMITERS   = {'(', ')', '{', '}', ';', ',', ':'}

    # Token names corresponding to operators for common internal representation
    _OPERATOR_TOKEN_NAMES = {
        "TOKEN_PLUS", "TOKEN_MINUS", "TOKEN_MULTIPLY", "TOKEN_DIVIDE",
        "TOKEN_EQ_CHECK", "TOKEN_GT", "TOKEN_LT", "TOKEN_GTE", "TOKEN_LTE", "TOKEN_NEQ",
        "TOKEN_AND", "TOKEN_OR", "TOKEN_NOT", "TOKEN_ASSIGN",
    }

    def __init__(
        self,
        translation_map: Dict[str, str],
        syntax_map: Dict[str, str],
        keyword_to_token_name: Dict[str, str],
    ):
        self.translation_map = translation_map
        self.syntax_map = syntax_map
        self.keyword_to_token_name = keyword_to_token_name

        # Pre-compile the identifier regex
        self._ident_re = re.compile(
            rf'^{_WORD_START}{_WORD_CHAR}*$'
        )
        # Pre-sort keyword list by length descending for greedy matching
        self._sorted_keywords = sorted(
            self.translation_map.keys(), key=len, reverse=True
        )
        # Build a set for fast "is this a keyword?" lookups
        self._keyword_set = set(self.translation_map.keys())

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------
    def tokenize(self, source: str) -> List[Token]:
        """
        Convert VITAL source code into a list of Token objects.

        The returned list always ends with a single EOF token.
        """
        tokens: List[Token] = []
        lines = source.split('\n')
        in_block_comment = False

        for line_num, line in enumerate(lines, start=1):
            col = 0
            line_len = len(line)

            # Strip trailing \r if present
            if line.endswith('\r'):
                line = line[:-1]
                line_len = len(line)

            while col < line_len:
                if in_block_comment:
                    end_idx = line.find('*/', col)
                    if end_idx != -1:
                        comment_text = line[col:end_idx + 2]
                        tokens.append(Token(
                            type=TokenType.COMMENT,
                            lexeme=comment_text,
                            value=comment_text,
                            line=line_num,
                            column=col + 1,
                        ))
                        col = end_idx + 2
                        in_block_comment = False
                        continue
                    else:
                        comment_text = line[col:]
                        tokens.append(Token(
                            type=TokenType.COMMENT,
                            lexeme=comment_text,
                            value=comment_text,
                            line=line_num,
                            column=col + 1,
                        ))
                        break

                ch = line[col]

                # --- Skip whitespace ---
                if ch in (' ', '\t'):
                    col += 1
                    continue

                # --- Block Comment (/* ... */) ---
                if ch == '/' and col + 1 < line_len and line[col + 1] == '*':
                    end_idx = line.find('*/', col + 2)
                    if end_idx != -1:
                        comment_text = line[col:end_idx + 2]
                        tokens.append(Token(
                            type=TokenType.COMMENT,
                            lexeme=comment_text,
                            value=comment_text,
                            line=line_num,
                            column=col + 1,
                        ))
                        col = end_idx + 2
                        continue
                    else:
                        comment_text = line[col:]
                        tokens.append(Token(
                            type=TokenType.COMMENT,
                            lexeme=comment_text,
                            value=comment_text,
                            line=line_num,
                            column=col + 1,
                        ))
                        in_block_comment = True
                        break

                # --- String literal ---
                if ch in ('"', "'"):
                    tok, col = self._read_string(line, col, line_num)
                    tokens.append(tok)
                    continue

                # --- Comment (# or //) ---
                if ch == '#' or (ch == '/' and col + 1 < line_len and line[col + 1] == '/'):
                    # Check if '#' is actually a keyword mapping (like टिप्पणी → #)
                    # In the existing system, # at the start of a lexeme after
                    # comment-keyword translation is treated as a Python comment.
                    # But source '#' or '//' are direct comments.
                    comment_text = line[col:]
                    tokens.append(Token(
                        type=TokenType.COMMENT,
                        lexeme=comment_text,
                        value=comment_text,
                        line=line_num,
                        column=col + 1,
                    ))
                    break  # rest of line is comment

                # --- Two-character operators ---
                if col + 1 < line_len:
                    two = line[col:col+2]
                    if two in self._TWO_CHAR_OPS:
                        token_name = ""
                        py_val = two
                        if two in self._keyword_set:
                            py_val = self.translation_map[two]
                            token_name = self.keyword_to_token_name.get(two, "")
                        tokens.append(Token(
                            type=TokenType.OPERATOR,
                            lexeme=two,
                            value=py_val,
                            line=line_num,
                            column=col + 1,
                            token_name=token_name,
                        ))
                        col += 2
                        continue

                # --- Single-character operators ---
                if ch in self._ONE_CHAR_OPS:
                    token_name = ""
                    py_val = ch
                    if ch in self._keyword_set:
                        py_val = self.translation_map[ch]
                        token_name = self.keyword_to_token_name.get(ch, "")
                    tokens.append(Token(
                        type=TokenType.OPERATOR,
                        lexeme=ch,
                        value=py_val,
                        line=line_num,
                        column=col + 1,
                        token_name=token_name,
                    ))
                    col += 1
                    continue

                # --- Delimiters ---
                if ch in self._DELIMITERS:
                    tokens.append(Token(
                        type=TokenType.DELIMITER,
                        lexeme=ch,
                        value=ch,
                        line=line_num,
                        column=col + 1,
                    ))
                    col += 1
                    continue

                # --- Number literal ---
                if ch.isdigit():
                    tok, col = self._read_number(line, col, line_num)
                    tokens.append(tok)
                    continue

                # --- Word (keyword or identifier) ---
                if self._is_word_start(ch):
                    tok, col = self._read_word(line, col, line_num)
                    tokens.append(tok)
                    continue

                # --- Stray backtick: lexical error ---
                if ch == '`':
                    raise LexerError(f"unexpected backtick at line {line_num}:{col + 1}")

                # --- Unknown character: skip ---
                col += 1

        # Append EOF sentinel
        last_line = len(lines)
        tokens.append(Token(
            type=TokenType.EOF,
            lexeme="",
            value="",
            line=last_line,
            column=0,
        ))
        return tokens

    # -----------------------------------------------------------------
    # Lexer Log Generation
    # -----------------------------------------------------------------
    def write_log(self, tokens: List[Token], log_path: str) -> None:
        """
        Write a human-readable lexer log showing tokens grouped by line.

        This preserves the existing project's lexer-log feature while
        enhancing it with structured token information including
        line/column positions and internal token names.
        """
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, 'w', encoding='utf-8') as f:
            f.write("--- LEXICAL ANALYSIS REPORT ---\n")
            f.write("--- Generated by VITAL Real Lexer (Token Pipeline) ---\n\n")

            current_line = -1
            for tok in tokens:
                if tok.type == TokenType.EOF:
                    break
                if tok.type == TokenType.NEWLINE:
                    continue

                if tok.line != current_line:
                    if current_line != -1:
                        f.write("\n")
                    current_line = tok.line
                    f.write(f"Line {tok.line}:\n")

                # Format: TYPE("lexeme") [→ value] @ C<col>
                if tok.type in (TokenType.KEYWORD, TokenType.OPERATOR):
                    if tok.token_name:
                        f.write(f"  {tok.type.name}(\"{tok.lexeme}\") → {tok.token_name} → \"{tok.value}\"  @ C{tok.column}\n")
                    else:
                        f.write(f"  {tok.type.name}(\"{tok.lexeme}\") → \"{tok.value}\"  @ C{tok.column}\n")
                elif tok.type == TokenType.COMMENT:
                    f.write(f"  {tok.type.name}(\"{tok.lexeme[:60]}...\")  @ C{tok.column}\n"
                            if len(tok.lexeme) > 60
                            else f"  {tok.type.name}(\"{tok.lexeme}\")  @ C{tok.column}\n")
                else:
                    f.write(f"  {tok.type.name}(\"{tok.lexeme}\")  @ C{tok.column}\n")

            f.write(f"\n--- END OF LEXICAL ANALYSIS ({current_line} lines processed) ---\n")

    # -----------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------
    def _is_word_start(self, ch: str) -> bool:
        """Check if character can start a word (letter, underscore, or Indic script)."""
        if ch == '_' or ch.isalpha():
            return True
        cp = ord(ch)
        # Devanagari
        if 0x0900 <= cp <= 0x097F:
            return True
        # Bengali
        if 0x0980 <= cp <= 0x09FF:
            return True
        # Telugu
        if 0x0C00 <= cp <= 0x0C7F:
            return True
        return False

    def _is_word_char(self, ch: str) -> bool:
        """Check if character can continue a word."""
        if ch == '_' or ch.isalnum():
            return True
        cp = ord(ch)
        if 0x0900 <= cp <= 0x097F:
            return True
        if 0x0980 <= cp <= 0x09FF:
            return True
        if 0x0C00 <= cp <= 0x0C7F:
            return True
        return False

    def _read_string(self, line: str, start: int, line_num: int):
        """Read a quoted string literal. Returns (Token, new_col)."""
        quote = line[start]
        col = start + 1
        while col < len(line) and line[col] != quote:
            if line[col] == '\\':
                col += 1  # skip escaped character
            col += 1
        if col < len(line):
            col += 1  # skip closing quote
        lexeme = line[start:col]
        # Value is the string content without quotes
        value = lexeme[1:-1] if len(lexeme) >= 2 else lexeme
        return Token(
            type=TokenType.STRING,
            lexeme=lexeme,
            value=value,
            line=line_num,
            column=start + 1,
        ), col

    def _read_number(self, line: str, start: int, line_num: int):
        """Read a numeric literal. Returns (Token, new_col)."""
        col = start
        has_dot = False
        while col < len(line):
            ch = line[col]
            if ch.isdigit():
                col += 1
            elif ch == '.' and not has_dot:
                has_dot = True
                col += 1
            else:
                break
        lexeme = line[start:col]
        return Token(
            type=TokenType.NUMBER,
            lexeme=lexeme,
            value=lexeme,
            line=line_num,
            column=start + 1,
        ), col

    def _read_word(self, line: str, start: int, line_num: int):
        """
        Read a word token (keyword or identifier).

        Uses greedy matching: if the word matches a keyword in the
        translation map, it is classified as KEYWORD.  Otherwise
        it is an IDENTIFIER.

        Returns (Token, new_col).
        """
        col = start
        while col < len(line) and self._is_word_char(line[col]):
            col += 1
        lexeme = line[start:col]

        # Check if this word is a recognised keyword / stop-word
        if lexeme in self._keyword_set:
            py_val = self.translation_map[lexeme]
            token_name = self.keyword_to_token_name.get(lexeme, "")

            # Determine if this is a comment-introducing keyword
            # (like टिप्पणी, వ్యాఖ్య which map to "#")
            if py_val == "#":
                # Treat rest of line as comment
                comment_text = line[start:]
                return Token(
                    type=TokenType.COMMENT,
                    lexeme=comment_text,
                    value=comment_text,
                    line=line_num,
                    column=start + 1,
                    token_name="COMMENT",
                ), len(line)

            # Verbal operator words (like जोड़, కలుపు, add, etc.) are classified
            # as TokenType.OPERATOR so that all languages share the exact same internal representation.
            tok_type = (
                TokenType.OPERATOR
                if token_name in self._OPERATOR_TOKEN_NAMES
                else TokenType.KEYWORD
            )

            return Token(
                type=tok_type,
                lexeme=lexeme,
                value=py_val,
                line=line_num,
                column=start + 1,
                token_name=token_name,
            ), col

        # Otherwise it is a user identifier
        return Token(
            type=TokenType.IDENTIFIER,
            lexeme=lexeme,
            value=lexeme,
            line=line_num,
            column=start + 1,
        ), col
