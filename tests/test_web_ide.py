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
import subprocess

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
        self.assertEqual(data.get('total_count', 0), 86)
        
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


class TestUIConsistencyBugs(unittest.TestCase):
    """
    Validation for UI consistency bug fixes:
      BUG 1: No placeholder ("Compilation Incomplete") after completion with Stage 14 completed.
      BUG 2: Stage 14 drawer reflects current run state directly (no gate message when 1-10 passed/warned; accurate label).
      BUG 3: Catalog count stays 86 even with automatic working copy present in examples/saved/working_copies.
    """

    def setUp(self):
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def test_catalog_count_stays_86_with_working_copy_present(self):
        """BUG 3: Catalog count is 86 and excludes automatic working copies in examples/saved/working_copies."""
        resp = self.client.get('/api/demos')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json().get('data', {})
        self.assertEqual(data.get('total_count'), 86, "Catalog count must be exactly 86.")

        # Ensure no working copies are in demos list
        for d in data.get('demos', []):
            self.assertNotIn("working_copies", d['path'], f"Working copy found in catalog: {d['path']}")

        # Create temporary working copy to verify it remains excluded
        working_copies_dir = os.path.join(PROJECT_ROOT, 'examples', 'saved', 'working_copies', 'test_dir')
        os.makedirs(working_copies_dir, exist_ok=True)
        probe_path = os.path.join(working_copies_dir, 'probe_autocopy.vital')
        try:
            with open(probe_path, 'w', encoding='utf-8') as f:
                f.write('print("Auto working copy probe")\n')

            resp2 = self.client.get('/api/demos')
            data2 = resp2.get_json().get('data', {})
            self.assertEqual(data2.get('total_count'), 86, "Catalog count must remain 86 with working copy present.")
            for d in data2.get('demos', []):
                self.assertNotIn("probe_autocopy.vital", d['path'])
        finally:
            if os.path.exists(probe_path):
                os.remove(probe_path)

        # Test that deliberate save via Save As (/api/save-file) appears in "My Saved Programs"
        save_name = "test_deliberate_save_as.vital"
        save_resp = self.client.post(
            '/api/save-file',
            json={"filename": save_name, "code": 'print("Deliberately saved")\n'}
        )
        self.assertEqual(save_resp.status_code, 200)
        saved_file_path = os.path.join(PROJECT_ROOT, 'examples', 'saved', save_name)
        try:
            resp3 = self.client.get('/api/demos')
            data3 = resp3.get_json().get('data', {})
            self.assertEqual(data3.get('total_count'), 87)
            self.assertIn("My Saved Programs", data3.get('categories_order', []))
            my_saved = data3.get('by_category', {}).get('My Saved Programs', [])
            self.assertTrue(any(item['filename'] == save_name for item in my_saved))
            # Backward-compatible alias
            user_saved = data3.get('by_category', {}).get('User Saved Programs', [])
            self.assertTrue(any(item['filename'] == save_name for item in user_saved))
        finally:
            if os.path.exists(saved_file_path):
                os.remove(saved_file_path)

    def test_drawer_state_after_completed_run(self):
        """BUG 2: Stage 14 drawer reads current run state: no gate when mandatory 1-10 passed, accurate label."""
        # 1. Verify backend pipeline run marks mandatory stages 1-10 and stage 14 completed
        hello_path = os.path.join(PROJECT_ROOT, 'examples', 'english', 'hello.vital')
        with open(hello_path, 'r', encoding='utf-8') as f:
            code = f.read()

        run_resp = self.client.post('/api/pipeline/run', json={"code": code, "language": "English", "use_ai_security": False})
        self.assertEqual(run_resp.status_code, 200)
        run_data = run_resp.get_json()
        stages = {s['id']: s['status'] for s in run_data.get('stages', [])}
        mandatory_stages = [
            "source_input", "lexical_analysis", "syntax_analysis", "ast_construction",
            "semantic_analysis", "symbol_table", "ir_generation", "optimization",
            "code_generation", "code_validation"
        ]
        for ms in mandatory_stages:
            self.assertIn(stages.get(ms), ('completed', 'passed', 'warning'), f"Mandatory stage {ms} did not pass")
        self.assertIn(stages.get('final_report'), ('completed', 'passed'))

        # 2. Test JS drawer state rendering in ide.js using Node.js
        node_script = r'''
const mockEl = (id) => ({
  id,
  style: {},
  classList: {
    classes: new Set(),
    add(c) { this.classes.add(c); },
    remove(c) { this.classes.delete(c); },
    contains(c) { return this.classes.has(c); }
  },
  addEventListener: () => {},
  innerHTML: '',
  textContent: '',
  setAttribute: () => {},
  appendChild: () => {}
});

const elementsStore = {};
global.document = {
  getElementById: (id) => {
    if (!elementsStore[id]) elementsStore[id] = mockEl(id);
    return elementsStore[id];
  },
  querySelector: (s) => mockEl(s),
  querySelectorAll: () => [],
  createElement: (t) => mockEl(t),
  addEventListener: () => {}
};
global.window = { addEventListener: () => {} };
global.localStorage = { getItem: () => null, setItem: () => {} };
global.fetch = () => Promise.resolve({ json: () => Promise.resolve({ success: true, data: { total_count: 86, by_language: {}, by_category: {}, languages_order: [], categories_order: [] } }) });
global.CodeMirror = { fromTextArea: () => ({ getValue: () => 'print(1)', setValue: () => {}, on: () => {}, refresh: () => {}, clearHistory: () => {}, getCursor: () => ({ line: 0, ch: 0 }), setCursor: () => {} }) };

const fs = require('fs');
let code = fs.readFileSync('web/static/js/ide.js', 'utf8');
code = code.replace('(function() {', 'global.__TEST_IDE = (function() {');
const lastIdx = code.lastIndexOf('})();');
code = code.substring(0, lastIdx) + 'return { state, elements, handlePipelineEvent, renderFinalReportStage }; })();';
eval(code);

const { state, elements, renderFinalReportStage } = global.__TEST_IDE;

// Scenario A: Completed run with stages 1-10 passed, 1 passed + 2 warnings in 11-13
state.editor = { getValue: () => 'print(1)', getCursor: () => ({ line: 0, ch: 0 }), setCursor: () => {} };
state.pipeline.compiledSource = 'print(1)';
state.pipeline.runRevision = 1;
state.sourceRevisionId = 1;
state.pipeline.isFinished = true;
state.pipeline.finishStatus = 'warning';

const mandatory = [
  'source_input', 'lexical_analysis', 'syntax_analysis', 'ast_construction',
  'semantic_analysis', 'symbol_table', 'ir_generation', 'optimization',
  'code_generation', 'code_validation'
];
mandatory.forEach(id => {
  state.pipeline.stageData[id] = { status: 'completed', duration_ms: 10, summary: 'OK' };
});
state.pipeline.stageData['security_analysis'] = { status: 'completed', duration_ms: 5 };
state.pipeline.stageData['ai_security_analysis'] = { status: 'warning', duration_ms: 5 };
state.pipeline.stageData['sandbox_execution'] = { status: 'warning', duration_ms: 5 };
state.pipeline.stageData['final_report'] = { status: 'completed', duration_ms: 5 };

renderFinalReportStage(state.pipeline.stages[13], state.pipeline.stageData['final_report'], 'warning', 5, 'BACKEND');
const bodyA = elements.drawerStageBody.innerHTML;

const results = {
  scenarioA_gateBlocked: bodyA.includes('Completion Gate Blocked'),
  scenarioA_reportGenerated: bodyA.includes('Final Report Generated'),
  scenarioA_accuracyLabel: bodyA.match(/Mandatory stages \(1-10\)[^<]*/)?.[0] || '',
  scenarioA_pipelineStatus: bodyA.includes('COMPLETED WITH WARNINGS') || bodyA.includes('SUCCESSFUL / COMPLETE')
};

// Scenario B: No run exists for current revision
state.pipeline.compiledSource = 'print(2)'; // source modified
state.pipeline.isFinished = false;
renderFinalReportStage(state.pipeline.stages[13], state.pipeline.stageData['final_report'], 'pending', 0, 'BACKEND');
const bodyB = elements.drawerStageBody.innerHTML;
results.scenarioB_gateBlocked = bodyB.includes('Completion Gate Blocked');
results.scenarioB_pendingPrereqs = bodyB.includes('PENDING PREREQUISITES');

// Scenario C: Mandatory stage failed
state.pipeline.compiledSource = 'print(1)';
state.pipeline.isFinished = true;
state.pipeline.stageData['syntax_analysis'] = { status: 'failed', duration_ms: 5, summary: 'Syntax error' };
renderFinalReportStage(state.pipeline.stages[13], state.pipeline.stageData['final_report'], 'failed', 5, 'BACKEND');
const bodyC = elements.drawerStageBody.innerHTML;
results.scenarioC_gateBlocked = bodyC.includes('Completion Gate Blocked');

console.log(JSON.stringify(results));
'''
        proc = subprocess.run(['node', '-e', node_script], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"Node script error: {proc.stderr}")
        res = json.loads(proc.stdout.strip().splitlines()[-1])

        # Scenario A: Completed run
        self.assertFalse(res['scenarioA_gateBlocked'], "Drawer must NOT show gate blocked after completed run")
        self.assertTrue(res['scenarioA_reportGenerated'], "Drawer must show 'Final Report Generated' directly")
        self.assertTrue(res['scenarioA_pipelineStatus'], "Pipeline status must show successful/completed")
        self.assertIn("Mandatory stages (1-10): 10/10 passed", res['scenarioA_accuracyLabel'])
        self.assertIn("Stages 11-13: 1 passed, 2 warnings", res['scenarioA_accuracyLabel'])

        # Scenario B & C: Gate shown when no run or mandatory stage failed
        self.assertTrue(res['scenarioB_gateBlocked'], "Drawer must show gate blocked when no run exists for revision")
        self.assertTrue(res['scenarioB_pendingPrereqs'], "Drawer must show PENDING PREREQUISITES when no run exists")
        self.assertTrue(res['scenarioC_gateBlocked'], "Drawer must show gate blocked when mandatory stage failed")

    def test_no_placeholder_after_completion(self):
        """BUG 1: No placeholder ('Compilation Incomplete') after run completes with Stage 14 completed."""
        node_script = r'''
const mockEl = (id) => ({
  id,
  style: {},
  classList: {
    classes: new Set(),
    add(c) { this.classes.add(c); },
    remove(c) { this.classes.delete(c); },
    contains(c) { return this.classes.has(c); }
  },
  addEventListener: () => {},
  innerHTML: '',
  textContent: '',
  setAttribute: () => {},
  appendChild: () => {}
});

const elementsStore = {};
global.document = {
  getElementById: (id) => {
    if (!elementsStore[id]) elementsStore[id] = mockEl(id);
    return elementsStore[id];
  },
  querySelector: (s) => mockEl(s),
  querySelectorAll: () => [],
  createElement: (t) => mockEl(t),
  addEventListener: () => {}
};
global.window = { addEventListener: () => {} };
global.localStorage = { getItem: () => null, setItem: () => {} };
global.fetch = () => Promise.resolve({ json: () => Promise.resolve({ success: true, data: { total_count: 86, by_language: {}, by_category: {}, languages_order: [], categories_order: [] } }) });
global.CodeMirror = { fromTextArea: () => ({ getValue: () => 'print(1)', setValue: () => {}, on: () => {}, refresh: () => {}, clearHistory: () => {}, getCursor: () => ({ line: 0, ch: 0 }), setCursor: () => {} }) };

const fs = require('fs');
let code = fs.readFileSync('web/static/js/ide.js', 'utf8');
code = code.replace('(function() {', 'global.__TEST_IDE = (function() {');
const lastIdx = code.lastIndexOf('})();');
code = code.substring(0, lastIdx) + 'return { state, elements, handlePipelineEvent, showOutputWaitingState }; })();';
eval(code);

const { state, elements, handlePipelineEvent, showOutputWaitingState } = global.__TEST_IDE;

state.editor = { getValue: () => 'print(1)', getCursor: () => ({ line: 0, ch: 0 }), setCursor: () => {} };
state.pipeline.compiledSource = 'print(1)';
state.pipeline.runRevision = 1;
state.sourceRevisionId = 1;

const mandatory = [
  'source_input', 'lexical_analysis', 'syntax_analysis', 'ast_construction',
  'semantic_analysis', 'symbol_table', 'ir_generation', 'optimization',
  'code_generation', 'code_validation'
];
mandatory.forEach(id => {
  state.pipeline.stageData[id] = { status: 'completed', duration_ms: 10, summary: 'OK' };
});
state.pipeline.stageData['final_report'] = { status: 'completed', duration_ms: 5 };

// 1. Pipeline finishes with status warning and stage 14 complete
handlePipelineEvent({
  event: 'pipeline_finish',
  status: 'warning',
  artifacts: { output: 'hello output', ir_code: 'test ir' }
});

const res = {
  completed_waitingStateDisplay: elements.outputWaitingState.style.display,
  completed_tabsBarDisplay: elements.outputTabsBar.style.display,
  completed_contentAreaDisplay: elements.outputContentArea.style.display
};

// 2. Failure case: Mandatory stage failed
state.pipeline.stageData['optimization'] = { status: 'failed', duration_ms: 5, summary: 'Optimization error' };
handlePipelineEvent({
  event: 'pipeline_finish',
  status: 'failed'
});

res.failed_waitingStateDisplay = elements.outputWaitingState.style.display;
res.failed_waitingMessage = elements.outputWaitingMessage.textContent;

// 3. Reset case: source modified
showOutputWaitingState(
  "Source Modified — Re-compilation Needed",
  "Editor working buffer has changed. Click 'Run' to execute the sequential compiler pipeline on the new source."
);
res.reset_waitingStateDisplay = elements.outputWaitingState.style.display;
res.reset_waitingMessage = elements.outputWaitingMessage.textContent;

console.log(JSON.stringify(res));
'''
        proc = subprocess.run(['node', '-e', node_script], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"Node script error: {proc.stderr}")
        res = json.loads(proc.stdout.strip().splitlines()[-1])

        # After completed run: waiting state hidden, tabs shown
        self.assertEqual(res['completed_waitingStateDisplay'], 'none')
        self.assertEqual(res['completed_tabsBarDisplay'], 'flex')
        self.assertEqual(res['completed_contentAreaDisplay'], 'block')

        # When mandatory stage failed: waiting state visible with Compilation Incomplete
        self.assertEqual(res['failed_waitingStateDisplay'], 'flex')
        self.assertEqual(res['failed_waitingMessage'], 'Compilation Incomplete')

        # When source changed: resets correctly to Source Modified
        self.assertEqual(res['reset_waitingStateDisplay'], 'flex')
        self.assertIn('Source Modified', res['reset_waitingMessage'])
        self.assertIn('Re-compilation Needed', res['reset_waitingMessage'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
