# -*- coding: utf-8 -*-
"""
tests/test_web_ide.py — Integration and Regression Test Suite for VITAL Web IDE

Validates:
  1. Web API endpoints (health, demos list, demo content, run)
  2. Security: Path traversal protection, file extension enforcement
  3. Language execution across all 6 supported languages:
     English, Hindi, Telugu, Bengali, Marathi, Nepali
  4. Multilingual fusion program execution
  5. Error diagnostics: Syntax errors, parser errors, empty input, timeout
  6. Regression test: Web IDE execution matches direct Compiler execution
"""

import os
import sys
import json
import unittest

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(PROJECT_ROOT, 'src')
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from web.server import app
from web.compiler_runner import run_pipeline
from main import Compiler, RULES_FILE


class TestWebIDEEndpoints(unittest.TestCase):
    """Test Flask Web IDE routes and REST API."""

    def setUp(self):
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def test_homepage_loads(self):
        """Verify the main IDE HTML page loads successfully."""
        resp = self.client.get('/')
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("VITAL IDE", html)
        self.assertIn("MULTILINGUAL", html)
        self.assertIn("Explorer", html)
        self.assertIn("code-editor", html)
        self.assertIn("btn-run", html)

    def test_toolbar_layout_and_controls_order(self):
        """Verify the toolbar places program name, Run, and AI Assistant together in order, with no theme toggle."""
        resp = self.client.get('/')
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        
        # 1. Theme toggle must be completely removed
        self.assertNotIn("btn-theme", html)
        self.assertNotIn("theme-icon", html)
        
        # 2. Key toolbar controls must be present
        self.assertIn("header-file-badge", html)
        self.assertIn("btn-run", html)
        self.assertIn("btn-ai-assistant", html)
        
        # 3. Order verification: [header-file-badge] -> [btn-run] -> [btn-ai-assistant]
        pos_badge = html.index("header-file-badge")
        pos_run = html.index("btn-run")
        pos_ai = html.index("btn-ai-assistant")
        self.assertLess(pos_badge, pos_run, "Language/program name must precede Run button")
        self.assertLess(pos_run, pos_ai, "Run button must precede AI Assistant button")
        
        # 4. Secondary group follows primary group
        pos_new = html.index("btn-new")
        pos_open = html.index("btn-open")
        pos_save = html.index("btn-save")
        pos_reset = html.index("btn-reset")
        pos_clear = html.index("btn-clear")
        self.assertLess(pos_ai, pos_new, "AI Assistant button must precede secondary actions")
        self.assertLess(pos_new, pos_open)
        self.assertLess(pos_open, pos_save)
        self.assertLess(pos_save, pos_reset)
        self.assertLess(pos_reset, pos_clear)

    def test_light_theme_only_enforcement(self):
        """Verify light-theme-only rules in frontend CSS and JS assets."""
        css_path = os.path.join(PROJECT_ROOT, 'web', 'static', 'css', 'ide.css')
        with open(css_path, 'r', encoding='utf-8') as f:
            css = f.read()
        
        # No body.light-theme override block (light theme is default and only)
        self.assertNotIn("body.light-theme", css)
        self.assertIn("--bg-editor: #FFFFFF", css)
        self.assertIn("--bg-app: #F8FAFC", css)
        self.assertIn("--bg-sidebar: #F1F5F9", css)
        self.assertIn("--primary-blue: #2563EB", css)
        
        js_path = os.path.join(PROJECT_ROOT, 'web', 'static', 'js', 'ide.js')
        with open(js_path, 'r', encoding='utf-8') as f:
            js = f.read()
        
        self.assertNotIn("toggleTheme", js)
        self.assertNotIn('theme: "dark"', js)
        self.assertIn("btnAiAssistant", js)

    def test_health_endpoint(self):
        """Verify health check returns service metadata."""
        resp = self.client.get('/api/health')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get('status'), 'healthy')
        self.assertEqual(len(data.get('supported_languages', [])), 6)

    def test_demos_list_endpoint(self):
        """Verify discovery of demo files across languages and categories."""
        resp = self.client.get('/api/demos')
        self.assertEqual(resp.status_code, 200)
        json_data = resp.get_json()
        self.assertTrue(json_data.get('success'))
        data = json_data.get('data', {})
        self.assertGreaterEqual(data.get('total_count', 0), 24)
        
        # Verify all 6 languages are represented in by_language
        by_lang = data.get('by_language', {})
        for lang in ['English', 'Hindi', 'Telugu', 'Bengali', 'Marathi', 'Nepali']:
            self.assertIn(lang, by_lang)
            self.assertGreater(len(by_lang[lang]), 0, f"No demo files for {lang}")

    def test_demo_content_fetch(self):
        """Verify reading a demo file safely."""
        resp = self.client.get('/api/demo-content?path=examples/english/hello.vital')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get('success'))
        self.assertEqual(data.get('filename'), 'hello.vital')
        self.assertIn('print', data.get('code', ''))

    def test_security_path_traversal_blocked(self):
        """Security: Path traversal attempts must be denied."""
        evil_paths = [
            '../../etc/passwd',
            '..\\..\\windows\\win.ini',
            '../../../app.py',
            '/etc/shadow'
        ]
        for path in evil_paths:
            resp = self.client.get(f'/api/demo-content?path={path}')
            self.assertNotEqual(resp.status_code, 200, f"Path traversal succeeded for {path}!")

    def test_security_non_vital_file_blocked(self):
        """Security: Only .vital files can be accessed via demo-content."""
        resp = self.client.get('/api/demo-content?path=src/main.py')
        self.assertNotEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data.get('success'))

    def test_run_empty_code(self):
        """Verify empty code returns a clear error message."""
        resp = self.client.post('/api/run', json={"code": ""})
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertFalse(data.get('success'))
        self.assertEqual(data.get('execution_status'), 'empty')


class TestMultilingualCompilerExecution(unittest.TestCase):
    """Test web compiler execution across all 6 languages."""

    def setUp(self):
        self.client = app.test_client()

    def _run_vital(self, code, language=""):
        resp = self.client.post('/api/run', json={"code": code, "language": language})
        self.assertEqual(resp.status_code, 200)
        return resp.get_json()

    def test_english_execution(self):
        code = "let x = 10\nlet y = 20\nlet z = x + y\nprint(z)"
        res = self._run_vital(code, "English")
        self.assertTrue(res['success'])
        self.assertIn('30', res['output'])
        self.assertEqual(res['execution_status'], 'completed')
        self.assertGreater(len(res['lexer_log']), 0)
        self.assertGreater(len(res['ir_code']), 0)

    def test_hindi_execution(self):
        code = "मानो a = 15\nमानो b = 25\nमानो c = a जोड़ b\nलिखो(c)"
        res = self._run_vital(code, "Hindi")
        self.assertTrue(res['success'])
        self.assertIn('40', res['output'])
        self.assertEqual(res['execution_status'], 'completed')

    def test_telugu_execution(self):
        code = "అనుకో a = 12\nఅనుకో b = 18\nఅనుకో c = a కలుపు b\nరాయి(c)"
        res = self._run_vital(code, "Telugu")
        self.assertTrue(res['success'])
        self.assertIn('30', res['output'])
        self.assertEqual(res['execution_status'], 'completed')

    def test_bengali_execution(self):
        code = "ধরো a = 50\nধরো b = 30\nধরো c = a বিয়োগ b\nছাপাও(c)"
        res = self._run_vital(code, "Bengali")
        self.assertTrue(res['success'])
        self.assertIn('20', res['output'])
        self.assertEqual(res['execution_status'], 'completed')

    def test_marathi_execution(self):
        code = "घ्या a = 10\nघ्या b = 20\nघ्या c = a जोडा b\nलिहा(c)"
        res = self._run_vital(code, "Marathi")
        self.assertTrue(res['success'])
        self.assertIn('30', res['output'])
        self.assertEqual(res['execution_status'], 'completed')

    def test_nepali_execution(self):
        code = "मान a = 10\nमान b = 20\nमान c = a जोड b\nछाप(c)"
        res = self._run_vital(code, "Nepali")
        self.assertTrue(res['success'])
        self.assertIn('30', res['output'])
        self.assertEqual(res['execution_status'], 'completed')

    def test_multilingual_fusion(self):
        """Verify program mixing Hindi, Telugu, and English keywords."""
        code = (
            "मानो x = 10\n"
            "అనుకో y = 20\n"
            "let z = x + y\n"
            "print(z)\n"
            "लिखो(z)\n"
            "రాయి(z)"
        )
        res = self._run_vital(code, "Multilingual Fusion")
        self.assertTrue(res['success'])
        self.assertIn('30', res['output'])

    def test_syntax_error_unbalanced_braces(self):
        """Verify unbalanced braces syntax error is cleanly reported."""
        code = "let x = 10\nif (x > 5) {\n    print(x)\n"  # missing closing brace
        res = self._run_vital(code, "English")
        self.assertFalse(res['success'])
        self.assertEqual(res['execution_status'], 'syntax_error')
        self.assertIn('Unbalanced brackets', res['parser_log'])

    def test_runtime_error_division_by_zero(self):
        """Verify runtime errors are captured gracefully without server crash."""
        code = "let x = 10 / 0\nprint(x)"
        res = self._run_vital(code, "English")
        self.assertFalse(res['success'])
        self.assertEqual(res['execution_status'], 'runtime_error')
        self.assertIn('division by zero', res['output'])


class TestDirectCompilerVsWebIDERegression(unittest.TestCase):
    """
    Regression Test:
    Compare direct execution of the existing Compiler in src/main.py
    against the Web IDE execution for cross-language equivalence programs.
    The outputs must match exactly.
    """

    def _run_direct_compiler(self, source_code):
        app_compiler = Compiler(RULES_FILE)
        app_compiler.load_rules()
        app_compiler.run_lexer(source_code)
        valid = app_compiler.run_parser(source_code)
        if not valid:
            return None, "Parser failed"
        ir = app_compiler.transpile(source_code)
        app_compiler.execute(ir)
        
        tests_dir = os.path.join(PROJECT_ROOT, 'tests')
        with open(os.path.join(tests_dir, 'output.txt'), 'r', encoding='utf-8') as f:
            return f.read().strip(), None

    def test_regression_all_six_equivalence_files(self):
        languages = ['english', 'hindi', 'telugu', 'bengali', 'marathi', 'nepali']
        
        for lang in languages:
            rel_path = f"src/tests/equiv_{lang}.vital"
            full_path = os.path.join(PROJECT_ROOT, rel_path)
            with open(full_path, 'r', encoding='utf-8') as f:
                code = f.read()

            # 1. Direct compiler execution
            direct_output, direct_err = self._run_direct_compiler(code)
            self.assertIsNone(direct_err, f"Direct compiler failed on {lang}")

            # 2. Web pipeline execution
            web_res = run_pipeline(code)
            self.assertTrue(web_res['success'], f"Web runner failed on {lang}: {web_res.get('status_message')}")
            web_output = web_res['output'].strip()

            # Compare outputs
            self.assertEqual(
                web_output, direct_output,
                f"Web IDE output differs from Direct Compiler for {lang}!\n"
                f"Direct: {repr(direct_output)}\n"
                f"Web:    {repr(web_output)}"
            )


if __name__ == '__main__':
    unittest.main(verbosity=2)
