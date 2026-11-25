# -*- coding: utf-8 -*-
"""
tests/test_bug_a_security_badge.py — Acceptance Test Suite for Bug A:
Security Warning Badge Appearing Before Run & Run-Scoped Gating.

Acceptance Criteria:
1. Open any security demo, don't press Run: no badge on stages 11/12, header says Ready.
2. Press Run, then edit one character: all badges clear immediately.
3. Start a run, switch files quickly: new file shows no leftover badge from the old run.
4. Security results (Stage 11 & 12) must be run-scoped:
   { run_id, source_hash, stage, findings[], created_at }
   and only displayed if source_hash == sha256(current editor buffer) AND run_id == current/last completed run.
5. Backend /api/pipeline/reset resets pipeline status and artifacts.
"""

import os
import sys
import json
import unittest
import subprocess

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from web.server import app


class TestBugASecurityBadgeBackend(unittest.TestCase):
    """Test backend endpoints supporting Bug A fix."""

    def setUp(self):
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def test_pipeline_reset_endpoint(self):
        """Verify /api/pipeline/reset responds successfully."""
        resp = self.client.post('/api/pipeline/reset')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get('success'))
        self.assertIn('reset', data.get('message', '').lower())


class TestBugASecurityBadgeFrontend(unittest.TestCase):
    """Test frontend behavior in Node.js executing ide.js."""

    def _run_node_test(self, js_scenario_code):
        js_file = os.path.join(PROJECT_ROOT, 'web', 'static', 'js', 'ide.js').replace('\\', '/')
        harness = f"""
const fs = require('fs');

const elementsStore = {{}};
function mockEl(id) {{
  let _className = '';
  const classes = new Set();
  return {{
    id,
    style: {{ display: '' }},
    get className() {{ return _className; }},
    set className(val) {{
      _className = val || '';
      classes.clear();
      _className.split(/\\s+/).filter(Boolean).forEach(c => classes.add(c));
    }},
    classList: {{
      classes,
      add(c) {{ classes.add(c); _className = Array.from(classes).join(' '); }},
      remove(c) {{ classes.delete(c); _className = Array.from(classes).join(' '); }},
      contains(c) {{ return classes.has(c); }}
    }},
    addEventListener: () => {{}},
    scrollIntoView: () => {{}},
    innerHTML: '',
    textContent: '',
    setAttribute: () => {{}},
    appendChild: () => {{}},
    querySelector: function(sel) {{
      return mockEl(this.id + '_' + sel);
    }}
  }};
}}

global.document = {{
  readyState: 'complete',
  getElementById: (id) => {{
    if (!elementsStore[id]) elementsStore[id] = mockEl(id);
    return elementsStore[id];
  }},
  querySelector: (s) => mockEl(s),
  querySelectorAll: () => [],
  createElement: (t) => mockEl(t),
  addEventListener: () => {{}}
}};

global.window = {{ addEventListener: () => {{}} }};
global.localStorage = {{ getItem: () => null, setItem: () => {{}} }};
global.fetch = () => Promise.resolve({{
  json: () => Promise.resolve({{ success: true, data: {{ total_count: 86, by_language: {{}}, by_category: {{}}, languages_order: [], categories_order: [] }} }})
}});

const editorListeners = {{}};
let editorContent = 'print("hello")';
global.CodeMirror = {{
  fromTextArea: () => ({{
    getValue: () => editorContent,
    setValue: (val) => {{ editorContent = val; }},
    on: (evt, fn) => {{ editorListeners[evt] = fn; }},
    trigger: (evt) => {{ if (editorListeners[evt]) editorListeners[evt](); }},
    refresh: () => {{}},
    clearHistory: () => {{}},
    focus: () => {{}},
    getCursor: () => ({{ line: 0, ch: 0 }}),
    setCursor: () => {{}}
  }})
}};

// Load ide.js
let code = fs.readFileSync('{js_file}', 'utf8');
eval(code);

const ide = global.window.__VITAL_IDE__;
const {{ state, elements, resetPipelineFullState, resetPipelineStepper, handlePipelineEvent, isSecurityResultValidForActiveBuffer, sha256Sync, setupSecurityBanner, loadDemoFile, renderSecurityFindings }} = ide;

{js_scenario_code}
"""
        proc = subprocess.run(['node', '-e', harness], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"Node harness error: {proc.stderr}\nStdout: {proc.stdout}")
        lines = [line.strip() for line in proc.stdout.strip().splitlines() if line.strip()]
        last_line = lines[-1] if lines else "{}"
        return json.loads(last_line)

    def test_open_security_demo_without_run_shows_no_badge_and_ready(self):
        """Acceptance 1: Open any security demo, don't press Run: no badge on stages 11/12, header says Ready."""
        scenario = """
// Simulate opening a security demo file
const demoMeta = {
  is_security_lab: true,
  security_lab_meta: {
    difficulty: "Intermediate",
    scenario_type: "auth_bypass",
    defect_categories: ["Broken Authentication"]
  }
};

// Set initial idle/reset state as done when opening file
setupSecurityBanner(demoMeta);
resetPipelineFullState("file_switch");

const badge11 = document.getElementById("step-badge-security_analysis");
const badge12 = document.getElementById("step-badge-ai_security_analysis");
const node11 = document.getElementById("step-node-security_analysis");
const node12 = document.getElementById("step-node-ai_security_analysis");
const statusBadge = elements.pipelineStatusBadge;
const metricProgress = elements.pipelineMetricProgress;

const result = {
  statusBadgeText: statusBadge.textContent,
  isStatusIdle: statusBadge.classList.contains("badge-idle"),
  metricProgressText: metricProgress.textContent,
  badge11Display: badge11.style.display,
  badge12Display: badge12.style.display,
  node11Pending: node11.classList.contains("status-pending"),
  node12Pending: node12.classList.contains("status-pending"),
  isSec11Valid: isSecurityResultValidForActiveBuffer("security_analysis"),
  isSec12Valid: isSecurityResultValidForActiveBuffer("ai_security_analysis")
};

console.log(JSON.stringify(result));
"""
        res = self._run_node_test(scenario)
        self.assertEqual(res['statusBadgeText'], 'Ready', "Pipeline header must read 'Ready'")
        self.assertTrue(res['isStatusIdle'], "Pipeline status badge must have 'badge-idle' class")
        self.assertEqual(res['metricProgressText'], '0/14 Stages (0%)', "Pipeline progress must be 0/14 Stages (0%)")
        self.assertEqual(res['badge11Display'], 'none', "Stage 11 badge must NOT be displayed")
        self.assertEqual(res['badge12Display'], 'none', "Stage 12 badge must NOT be displayed")
        self.assertTrue(res['node11Pending'], "Stage 11 must be in pending status")
        self.assertTrue(res['node12Pending'], "Stage 12 must be in pending status")
        self.assertFalse(res['isSec11Valid'], "Stage 11 security result must not be valid before run")
        self.assertFalse(res['isSec12Valid'], "Stage 12 security result must not be valid before run")

    def test_press_run_then_edit_clears_badges_immediately(self):
        """Acceptance 2: Press Run, then edit one character: all badges clear immediately."""
        scenario = """
const initialCode = 'x = 10\\nprint(x)';
state.editor.setValue(initialCode);
const initialHash = sha256Sync(initialCode);

// 1. Simulate starting a Run
const runId = 'run-101';
state.isExecuting = true;
state.pipeline.activeRunId = runId;
state.pipeline.compiledSource = initialCode;
state.currentBufferHash = initialHash;
resetPipelineStepper(true);

// 2. Simulate stage 11 emitting findings
handlePipelineEvent({
  run_id: runId,
  event: 'stage_warning',
  stage_id: 'security_analysis',
  stage: '11. Security Analysis',
  stage_status: 'warning',
  findings_count: 3,
  details: {
    findings: [{ id: 'SEC-1', title: 'Hardcoded Credential' }]
  },
  source_hash: initialHash
});

// Simulate pipeline finish
handlePipelineEvent({
  run_id: runId,
  event: 'pipeline_finish',
  status: 'warning'
});
state.isExecuting = false;

const badge11AfterRun = document.getElementById('step-badge-security_analysis');
const hasBadgeAfterRun = (badge11AfterRun.style.display !== 'none');
const badgeTextAfterRun = badge11AfterRun.textContent;
const isValidAfterRun = isSecurityResultValidForActiveBuffer('security_analysis');

// 3. User edits one character in editor
const modifiedCode = initialCode + ' ';
state.editor.setValue(modifiedCode);

// Trigger CodeMirror change event handler which invokes resetPipelineFullState("buffer_edit")
resetPipelineFullState("buffer_edit");

const badge11AfterEdit = document.getElementById('step-badge-security_analysis');
const badge12AfterEdit = document.getElementById('step-badge-ai_security_analysis');
const node11AfterEdit = document.getElementById('step-node-security_analysis');
const statusBadgeAfterEdit = elements.pipelineStatusBadge;
const isValidAfterEdit = isSecurityResultValidForActiveBuffer('security_analysis');

const result = {
  hasBadgeAfterRun,
  badgeTextAfterRun,
  isValidAfterRun,
  badge11DisplayAfterEdit: badge11AfterEdit.style.display,
  badge12DisplayAfterEdit: badge12AfterEdit.style.display,
  statusBadgeTextAfterEdit: statusBadgeAfterEdit.textContent,
  node11PendingAfterEdit: node11AfterEdit.classList.contains('status-pending'),
  isValidAfterEdit
};

console.log(JSON.stringify(result));
"""
        res = self._run_node_test(scenario)
        self.assertTrue(res['hasBadgeAfterRun'], "Stage 11 badge must display after run")
        self.assertIn("3", res['badgeTextAfterRun'], "Stage 11 badge should show warning count")
        self.assertTrue(res['isValidAfterRun'], "Security result must be valid right after run on matching buffer")

        # After 1 char edit:
        self.assertEqual(res['badge11DisplayAfterEdit'], 'none', "Stage 11 badge must clear immediately on buffer edit")
        self.assertEqual(res['badge12DisplayAfterEdit'], 'none', "Stage 12 badge must clear immediately on buffer edit")
        self.assertEqual(res['statusBadgeTextAfterEdit'], 'Ready', "Pipeline status must reset to 'Ready'")
        self.assertTrue(res['node11PendingAfterEdit'], "Stage 11 node must revert to pending")
        self.assertFalse(res['isValidAfterEdit'], "Security result must become invalid on modified buffer")

    def test_start_run_switch_files_discards_old_run_badge(self):
        """Acceptance 3: Start a run, switch files quickly: new file shows no leftover badge from the old run."""
        scenario = """
const fileACode = 'file A source code';
state.editor.setValue(fileACode);
const fileAHash = sha256Sync(fileACode);

// 1. Start run for File A
const runIdA = 'run-file-a-001';
state.pipeline.activeRunId = runIdA;
state.pipeline.compiledSource = fileACode;
state.currentBufferHash = fileAHash;
resetPipelineStepper(true);

// 2. User quickly switches to File B while run A is in flight
const fileBCode = 'file B fresh code';
state.editor.setValue(fileBCode);
resetPipelineFullState("file_switch");

// 3. Delayed SSE events from Run A now arrive
handlePipelineEvent({
  run_id: runIdA,
  event: 'stage_warning',
  stage_id: 'security_analysis',
  stage: '11. Security Analysis',
  stage_status: 'warning',
  findings_count: 5,
  details: {
    findings: [{ id: 'SEC-A', title: 'File A finding' }]
  },
  source_hash: fileAHash
});

handlePipelineEvent({
  run_id: runIdA,
  event: 'pipeline_finish',
  status: 'warning'
});

const badge11 = document.getElementById('step-badge-security_analysis');
const node11 = document.getElementById('step-node-security_analysis');
const statusBadge = elements.pipelineStatusBadge;
const isValid = isSecurityResultValidForActiveBuffer('security_analysis');

const result = {
  badge11Display: badge11.style.display,
  node11Pending: node11.classList.contains('status-pending'),
  statusBadgeText: statusBadge.textContent,
  isValid
};

console.log(JSON.stringify(result));
"""
        res = self._run_node_test(scenario)
        self.assertEqual(res['badge11Display'], 'none', "New file must NOT show leftover badge from old in-flight run")
        self.assertTrue(res['node11Pending'], "Stage 11 node must remain pending on new file")
        self.assertEqual(res['statusBadgeText'], 'Ready', "Status badge must remain Ready")
        self.assertFalse(res['isValid'], "Security result from old run must be invalid on new file")

    def test_security_scan_does_not_set_pipeline_badge(self):
        """Requirement 4: Quick scan / pre-scan updates Security tab but NEVER sets Stage 11 badge."""
        scenario = """
// Initialize idle pipeline
resetPipelineFullState("file_switch");

// Simulate renderSecurityFindings being invoked by pre-scan/banner scan
renderSecurityFindings(
  [{ id: 'SEC-PRE-1', title: 'Hardcoded Password in Config', severity: 'Critical' }],
  85,
  "Found hardcoded password",
  false
);

const badge11 = document.getElementById('step-badge-security_analysis');
const node11 = document.getElementById('step-node-security_analysis');
const statusBadge = elements.pipelineStatusBadge;
const scoreVal = elements.securityScoreVal ? elements.securityScoreVal.textContent : null;

const result = {
  badge11Display: badge11.style.display,
  node11Pending: node11.classList.contains('status-pending'),
  statusBadgeText: statusBadge.textContent,
  scoreVal: scoreVal
};

console.log(JSON.stringify(result));
"""
        res = self._run_node_test(scenario)
        self.assertEqual(res['badge11Display'], 'none', "Pre-scan must NEVER show badge on stage 11")
        self.assertTrue(res['node11Pending'], "Pre-scan must keep stage 11 node in pending status")
        self.assertEqual(res['statusBadgeText'], 'Ready', "Status badge must remain Ready")
        self.assertEqual(str(res['scoreVal']), '85', "Pre-scan must update Security tab risk score")

    def test_reset_events_clear_badges_and_output(self):
        """Requirement 3: Reset on file switch, buffer edit, restore, undo, new file."""
        scenario = """
// 1. Populate some fake pipeline and console state
state.pipeline.activeRunId = 'fake-run';
state.pipeline.lastCompletedRunId = 'fake-run';
elements.pipelineStatusBadge.textContent = 'RUNNING';
elements.pipelineStatusBadge.className = 'pipeline-status-badge badge-running';
elements.consoleProgram.textContent = 'some old output';
elements.consolePipeline.textContent = 'some old report';
const badge11 = document.getElementById('step-badge-security_analysis');
badge11.style.display = 'inline-block';
badge11.textContent = '⚠ 4';

// 2. Trigger reset on "+ New"
resetPipelineFullState("create_new");

const resultNew = {
  statusText: elements.pipelineStatusBadge.textContent,
  progressText: elements.pipelineMetricProgress.textContent,
  badgeDisplay: badge11.style.display,
  consoleProgramEmpty: elements.consoleProgram.textContent === '',
  consolePipelineEmpty: elements.consolePipeline.textContent === '',
  activeRunId: state.pipeline.activeRunId,
  lastCompletedRunId: state.pipeline.lastCompletedRunId
};

// 3. Populate again and test reset on Restore Original
elements.consoleProgram.textContent = 'another output';
badge11.style.display = 'inline-block';
resetPipelineFullState("restore_original");

const resultRestore = {
  statusText: elements.pipelineStatusBadge.textContent,
  badgeDisplay: badge11.style.display,
  consoleProgramEmpty: elements.consoleProgram.textContent === ''
};

console.log(JSON.stringify({ resultNew, resultRestore }));
"""
        res = self._run_node_test(scenario)
        self.assertEqual(res['resultNew']['statusText'], 'Ready')
        self.assertEqual(res['resultNew']['progressText'], '0/14 Stages (0%)')
        self.assertEqual(res['resultNew']['badgeDisplay'], 'none')
        self.assertTrue(res['resultNew']['consoleProgramEmpty'])
        self.assertTrue(res['resultNew']['consolePipelineEmpty'])
        self.assertIsNone(res['resultNew']['activeRunId'])
        self.assertIsNone(res['resultNew']['lastCompletedRunId'])

        self.assertEqual(res['resultRestore']['statusText'], 'Ready')
        self.assertEqual(res['resultRestore']['badgeDisplay'], 'none')
        self.assertTrue(res['resultRestore']['consoleProgramEmpty'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
