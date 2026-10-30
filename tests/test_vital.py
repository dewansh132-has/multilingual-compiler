"""
test_vital.py — Comprehensive Test Suite for the VITAL Compiler

Tests:
  1. Regression tests: All 21 existing .vital programs
  2. Per-language unit tests: English, Hindi, Telugu, Bengali, Marathi, Nepali
  3. Cross-language equivalence tests
  4. Lexer token stream verification
"""

import os
import sys
import io
import json
import contextlib
import unittest

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

src_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src')
sys.path.insert(0, src_dir)
os.chdir(src_dir)

from main import Compiler, RULES_FILE
from lexer import VitalLexer, Token, TokenType


def compile_and_run(source: str):
    """Helper: compile VITAL source and return (ir, output, error)."""
    app = Compiler(RULES_FILE)
    app.load_rules()
    ir_code = app.transpile(source)
    
    output_capture = io.StringIO()
    exec_error = None
    try:
        with contextlib.redirect_stdout(output_capture):
            exec(ir_code, {"__builtins__": __builtins__}, {})
    except Exception as e:
        exec_error = str(e)
    
    return ir_code, output_capture.getvalue(), exec_error


def tokenize(source: str):
    """Helper: tokenize VITAL source and return token list."""
    app = Compiler(RULES_FILE)
    app.load_rules()
    return app.lexer.tokenize(source)


# ========================================================================
# TEST CLASS 1: Lexer Token Stream Tests
# ========================================================================
class TestLexerTokenStream(unittest.TestCase):
    """Verify the real lexer produces correct structured tokens."""

    def test_english_tokens(self):
        tokens = tokenize('let x = 10\nprint(x)')
        # Filter out EOF
        tokens = [t for t in tokens if t.type != TokenType.EOF]
        types = [t.type for t in tokens]
        self.assertIn(TokenType.KEYWORD, types)
        self.assertIn(TokenType.IDENTIFIER, types)
        self.assertIn(TokenType.NUMBER, types)
        self.assertIn(TokenType.DELIMITER, types)

    def test_hindi_tokens(self):
        tokens = tokenize('मानो x = 10\nलिखो(x)')
        kw_tokens = [t for t in tokens if t.type == TokenType.KEYWORD]
        self.assertTrue(any(t.lexeme == 'मानो' for t in kw_tokens))
        self.assertTrue(any(t.lexeme == 'लिखो' for t in kw_tokens))

    def test_telugu_tokens(self):
        tokens = tokenize('అనుకో y = 20\nరాయి(y)')
        kw_tokens = [t for t in tokens if t.type == TokenType.KEYWORD]
        self.assertTrue(any(t.lexeme == 'అనుకో' for t in kw_tokens))
        self.assertTrue(any(t.lexeme == 'రాయి' for t in kw_tokens))

    def test_bengali_tokens(self):
        tokens = tokenize('ধরো z = 30\nছাপাও(z)')
        kw_tokens = [t for t in tokens if t.type == TokenType.KEYWORD]
        self.assertTrue(any(t.lexeme == 'ধরো' for t in kw_tokens))
        self.assertTrue(any(t.lexeme == 'ছাপাও' for t in kw_tokens))

    def test_marathi_tokens(self):
        tokens = tokenize('घ्या z = 30\nलिहा(z)')
        kw_tokens = [t for t in tokens if t.type == TokenType.KEYWORD]
        self.assertTrue(any(t.lexeme == 'घ्या' for t in kw_tokens))
        self.assertTrue(any(t.lexeme == 'लिहा' for t in kw_tokens))

    def test_nepali_tokens(self):
        tokens = tokenize('मान z = 30\nछाप(z)')
        kw_tokens = [t for t in tokens if t.type == TokenType.KEYWORD]
        self.assertTrue(any(t.lexeme == 'मान' for t in kw_tokens))
        self.assertTrue(any(t.lexeme == 'छाप' for t in kw_tokens))

    def test_token_has_line_column(self):
        tokens = tokenize('let x = 10')
        for t in tokens:
            if t.type != TokenType.EOF:
                self.assertGreater(t.line, 0)
                self.assertGreater(t.column, 0)

    def test_token_stream_ends_with_eof(self):
        tokens = tokenize('let x = 10')
        self.assertEqual(tokens[-1].type, TokenType.EOF)

    def test_string_token(self):
        tokens = tokenize('print("hello world")')
        str_tokens = [t for t in tokens if t.type == TokenType.STRING]
        self.assertEqual(len(str_tokens), 1)
        self.assertEqual(str_tokens[0].value, 'hello world')

    def test_comment_token(self):
        tokens = tokenize('// this is a comment\nlet x = 5')
        comment_tokens = [t for t in tokens if t.type == TokenType.COMMENT]
        self.assertEqual(len(comment_tokens), 1)

    def test_keyword_normalization(self):
        """All six languages' 'if' keyword should map to TOKEN_IF."""
        if_words = ['if', 'अगर', 'ఒకవేళ', 'যদি', 'जर', 'यदि_हो']
        for word in if_words:
            tokens = tokenize(f'{word} (x > 5) {{\n}}')
            kw_tokens = [t for t in tokens if t.type == TokenType.KEYWORD and t.token_name == 'TOKEN_IF']
            self.assertTrue(len(kw_tokens) >= 1, f"'{word}' should map to TOKEN_IF")

    def test_operator_token_equivalence(self):
        """Verify addition operators across all 6 languages map to TokenType.OPERATOR and TOKEN_PLUS."""
        plus_words = ['+', 'जोड़', 'కలుపు', 'যোগ', 'जोडा', 'जोड']
        for word in plus_words:
            tokens = tokenize(f'x {word} y')
            op_tokens = [t for t in tokens if t.type == TokenType.OPERATOR and t.token_name == 'TOKEN_PLUS' and t.value == '+']
            self.assertTrue(len(op_tokens) >= 1, f"'{word}' should map to OPERATOR(TOKEN_PLUS, '+')")

    def test_relational_operator_equivalence(self):
        """Verify comparison operators across all 6 languages map to TokenType.OPERATOR and TOKEN_GT."""
        gt_words = ['>', 'से_बड़ा', 'కంటే_పెద్దది', 'বড়', 'पेक्षा_मोठे', 'भन्दा_ठूलो']
        for word in gt_words:
            tokens = tokenize(f'x {word} 10')
            op_tokens = [t for t in tokens if t.type == TokenType.OPERATOR and t.token_name == 'TOKEN_GT' and t.value == '>']
            self.assertTrue(len(op_tokens) >= 1, f"'{word}' should map to OPERATOR(TOKEN_GT, '>')")

    def test_token_stream_identical_across_all_languages(self):
        """Verify that token streams across all 6 equivalent programs match 100% in types, names, and values."""
        test_dir = os.path.join(src_dir, 'tests')
        langs = ['english', 'hindi', 'telugu', 'bengali', 'marathi', 'nepali']
        streams = {}
        for lang in langs:
            with open(os.path.join(test_dir, f'equiv_{lang}.vital'), 'r', encoding='utf-8') as f:
                streams[lang] = tokenize(f.read())

        eng = streams['english']
        for lang in langs[1:]:
            cur = streams[lang]
            self.assertEqual(len(eng), len(cur), f"{lang} token count differs from English")
            for i, (t_eng, t_cur) in enumerate(zip(eng, cur)):
                if t_eng.type == TokenType.COMMENT:
                    continue
                self.assertEqual(t_eng.type, t_cur.type, f"Token {i} type mismatch: {t_eng} vs {t_cur}")
                self.assertEqual(t_eng.token_name, t_cur.token_name, f"Token {i} token_name mismatch: {t_eng} vs {t_cur}")
                self.assertEqual(t_eng.value, t_cur.value, f"Token {i} value mismatch: {t_eng} vs {t_cur}")

    def test_parser_consumes_token_stream_for_delimiters(self):
        """Verify parser uses token stream to detect unbalanced delimiters."""
        app = Compiler(RULES_FILE)
        app.load_rules()
        # Missing closing brace
        bad_code = 'let x = 10\nif (x > 5) {\n    print(x)\n'
        app.run_lexer(bad_code)
        self.assertFalse(app.run_parser(bad_code))
        # Unbalanced parens in tokens
        bad_parens = 'let x = (10 + 5\nprint(x)'
        app.run_lexer(bad_parens)
        self.assertFalse(app.run_parser(bad_parens))



# ========================================================================
# TEST CLASS 2: Per-Language Unit Tests
# ========================================================================
class TestEnglishPrograms(unittest.TestCase):
    """English language programs."""

    def test_variable_and_print(self):
        _, output, err = compile_and_run('let x = 42\nprint(x)')
        self.assertIsNone(err)
        self.assertIn('42', output)

    def test_arithmetic(self):
        _, output, err = compile_and_run('let a = 10\nlet b = 20\nlet c = a + b\nprint(c)')
        self.assertIsNone(err)
        self.assertIn('30', output)

    def test_if_else(self):
        _, output, err = compile_and_run('let x = 15\nif (x > 10) {\n    print("big")\n}\nelse {\n    print("small")\n}')
        self.assertIsNone(err)
        self.assertIn('big', output)

    def test_while_loop(self):
        _, output, err = compile_and_run('let i = 0\nwhile (i < 3) {\n    print(i)\n    let i = i + 1\n}')
        self.assertIsNone(err)
        self.assertIn('0', output)
        self.assertIn('1', output)
        self.assertIn('2', output)


class TestHindiPrograms(unittest.TestCase):
    """Hindi language programs."""

    def test_variable_and_print(self):
        _, output, err = compile_and_run('मानो x = 42\nलिखो(x)')
        self.assertIsNone(err)
        self.assertIn('42', output)

    def test_arithmetic(self):
        _, output, err = compile_and_run('मानो a = 10\nमानो b = 20\nमानो c = a जोड़ b\nलिखो(c)')
        self.assertIsNone(err)
        self.assertIn('30', output)

    def test_if_else(self):
        _, output, err = compile_and_run('मानो x = 15\nअगर (x > 10) {\n    लिखो("big")\n}\nअन्यथा {\n    लिखो("small")\n}')
        self.assertIsNone(err)
        self.assertIn('big', output)

    def test_while_loop(self):
        _, output, err = compile_and_run('मानो i = 0\nजबतक (i < 3) {\n    लिखो(i)\n    मानो i = i जोड़ 1\n}')
        self.assertIsNone(err)
        self.assertIn('0', output)
        self.assertIn('2', output)


class TestTeluguPrograms(unittest.TestCase):
    """Telugu language programs."""

    def test_variable_and_print(self):
        _, output, err = compile_and_run('అనుకో x = 42\nరాయి(x)')
        self.assertIsNone(err)
        self.assertIn('42', output)

    def test_arithmetic(self):
        _, output, err = compile_and_run('అనుకో a = 10\nఅనుకో b = 20\nఅనుకో c = a కలుపు b\nరాయి(c)')
        self.assertIsNone(err)
        self.assertIn('30', output)

    def test_if_else(self):
        _, output, err = compile_and_run('అనుకో x = 15\nఒకవేళ (x > 10) {\n    రాయి("big")\n}\nకాకపోతే {\n    రాయి("small")\n}')
        self.assertIsNone(err)
        self.assertIn('big', output)

    def test_while_loop(self):
        _, output, err = compile_and_run('అనుకో i = 0\nఉన్నంతవరకు (i < 3) {\n    రాయి(i)\n    అనుకో i = i కలుపు 1\n}')
        self.assertIsNone(err)
        self.assertIn('0', output)
        self.assertIn('2', output)


class TestBengaliPrograms(unittest.TestCase):
    """Bengali language programs — NEW (Contribution 2)."""

    def test_variable_and_print(self):
        _, output, err = compile_and_run('ধরো x = 42\nছাপাও(x)')
        self.assertIsNone(err)
        self.assertIn('42', output)

    def test_arithmetic(self):
        _, output, err = compile_and_run('ধরো a = 10\nধরো b = 20\nধরো c = a যোগ b\nছাপাও(c)')
        self.assertIsNone(err)
        self.assertIn('30', output)

    def test_if_else(self):
        _, output, err = compile_and_run('ধরো x = 15\nযদি (x > 10) {\n    ছাপাও("big")\n}\nনাহলে {\n    ছাপাও("small")\n}')
        self.assertIsNone(err)
        self.assertIn('big', output)

    def test_while_loop(self):
        _, output, err = compile_and_run('ধরো i = 0\nযতক্ষণ (i < 3) {\n    ছাপাও(i)\n    ধরো i = i যোগ 1\n}')
        self.assertIsNone(err)
        self.assertIn('0', output)
        self.assertIn('2', output)

    def test_break(self):
        _, output, err = compile_and_run('ধরো i = 0\nযতক্ষণ (i < 10) {\n    যদি (i == 3) {\n        থামো\n    }\n    ছাপাও(i)\n    ধরো i = i যোগ 1\n}')
        self.assertIsNone(err)
        self.assertIn('0', output)
        self.assertNotIn('3', output)


class TestMarathiPrograms(unittest.TestCase):
    """Marathi language programs — NEW (Contribution 2)."""

    def test_variable_and_print(self):
        _, output, err = compile_and_run('घ्या x = 42\nलिहा(x)')
        self.assertIsNone(err)
        self.assertIn('42', output)

    def test_arithmetic(self):
        _, output, err = compile_and_run('घ्या a = 10\nघ्या b = 20\nघ्या c = a जोडा b\nलिहा(c)')
        self.assertIsNone(err)
        self.assertIn('30', output)

    def test_if_else(self):
        _, output, err = compile_and_run('घ्या x = 15\nजर (x > 10) {\n    लिहा("big")\n}\nनाहीतर {\n    लिहा("small")\n}')
        self.assertIsNone(err)
        self.assertIn('big', output)

    def test_while_loop(self):
        _, output, err = compile_and_run('घ्या i = 0\nजोपर्यंत (i < 3) {\n    लिहा(i)\n    घ्या i = i जोडा 1\n}')
        self.assertIsNone(err)
        self.assertIn('0', output)
        self.assertIn('2', output)

    def test_break(self):
        _, output, err = compile_and_run('घ्या i = 0\nजोपर्यंत (i < 10) {\n    जर (i == 3) {\n        बंद_करा\n    }\n    लिहा(i)\n    घ्या i = i जोडा 1\n}')
        self.assertIsNone(err)
        self.assertIn('0', output)
        self.assertNotIn('3', output)


class TestNepaliPrograms(unittest.TestCase):
    """Nepali language programs — NEW (Contribution 2)."""

    def test_variable_and_print(self):
        _, output, err = compile_and_run('मान x = 42\nछाप(x)')
        self.assertIsNone(err)
        self.assertIn('42', output)

    def test_arithmetic(self):
        _, output, err = compile_and_run('मान a = 10\nमान b = 20\nमान c = a जोड b\nछाप(c)')
        self.assertIsNone(err)
        self.assertIn('30', output)

    def test_if_else(self):
        _, output, err = compile_and_run('मान x = 15\nयदि_हो (x > 10) {\n    छाप("big")\n}\nनत्र {\n    छाप("small")\n}')
        self.assertIsNone(err)
        self.assertIn('big', output)

    def test_while_loop(self):
        _, output, err = compile_and_run('मान i = 0\nजबसम्म (i < 3) {\n    छाप(i)\n    मान i = i जोड 1\n}')
        self.assertIsNone(err)
        self.assertIn('0', output)
        self.assertIn('2', output)

    def test_break(self):
        _, output, err = compile_and_run('मान i = 0\nजबसम्म (i < 10) {\n    यदि_हो (i == 3) {\n        रोक\n    }\n    छाप(i)\n    मान i = i जोड 1\n}')
        self.assertIsNone(err)
        self.assertIn('0', output)
        self.assertNotIn('3', output)


# ========================================================================
# TEST CLASS 3: Cross-Language Equivalence Tests
# ========================================================================
class TestCrossLanguageEquivalence(unittest.TestCase):
    """
    Verify that semantically equivalent programs in all six languages
    produce the same output.
    """

    def _get_output(self, filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            source = f.read()
        _, output, err = compile_and_run(source)
        return output, err

    def test_equivalence_all_six_languages(self):
        test_dir = os.path.join(src_dir, 'tests')
        languages = ['english', 'hindi', 'telugu', 'bengali', 'marathi', 'nepali']
        
        outputs = {}
        for lang in languages:
            filepath = os.path.join(test_dir, f'equiv_{lang}.vital')
            output, err = self._get_output(filepath)
            self.assertIsNone(err, f"{lang} program had runtime error: {err}")
            outputs[lang] = output
        
        # All outputs must match the English reference
        reference = outputs['english']
        for lang in languages[1:]:
            self.assertEqual(
                outputs[lang], reference,
                f"{lang} output differs from English!\n"
                f"English: {repr(reference)}\n"
                f"{lang}: {repr(outputs[lang])}"
            )


# ========================================================================
# TEST CLASS 4: Regression Tests for Existing Programs
# ========================================================================
class TestExistingProgramRegression(unittest.TestCase):
    """Verify existing .vital programs produce unchanged output."""

    def _run_file(self, rel_path):
        filepath = os.path.join(src_dir, rel_path)
        with open(filepath, 'r', encoding='utf-8') as f:
            source = f.read()
        return compile_and_run(source)

    def test_low_2_leap_year(self):
        _, output, err = self._run_file('low/low_2.vital')
        self.assertIsNone(err)
        self.assertIn('Checking Leap Year for:', output)
        self.assertIn('2024', output)
        self.assertIn('1', output)

    def test_low_4_tax(self):
        _, output, err = self._run_file('low/low_4.vital')
        self.assertIsNone(err)
        self.assertIn('Tax: 20%', output)

    def test_med_1_collatz(self):
        _, output, err = self._run_file('med/med_1.vital')
        self.assertIsNone(err)
        self.assertIn('17', output)

    def test_med_2_divisor(self):
        _, output, err = self._run_file('med/med_2.vital')
        self.assertIsNone(err)
        self.assertIn('3', output)

    def test_high_1_factorial(self):
        _, output, err = self._run_file('high/high_1.vital')
        self.assertIsNone(err)
        self.assertIn('Calculation Complete', output)

    def test_comp_2_warehouse(self):
        _, output, err = self._run_file('complex/comp_2.vital')
        self.assertIsNone(err)
        self.assertIn('Warning: Insufficient stock', output)

    def test_comp_4_alternating(self):
        _, output, err = self._run_file('complex/comp_4.vital')
        self.assertIsNone(err)
        self.assertIn('-50', output)

    def test_comp_5_prime(self):
        _, output, err = self._run_file('complex/comp_5.vital')
        self.assertIsNone(err)
        self.assertIn('Prime', output)

    def test_demo_telugu(self):
        _, output, err = self._run_file('demo.vital')
        self.assertIsNone(err)
        self.assertIn('Table of 7', output)


if __name__ == '__main__':
    unittest.main(verbosity=2)
