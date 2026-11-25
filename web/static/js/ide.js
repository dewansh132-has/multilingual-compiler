/**
 * web/static/js/ide.js — Core Client Logic for VITAL Multilingual IDE
 * 
 * Features:
 *   - CodeMirror integration with multilingual syntax highlighting
 *   - Explorer tree loading & dynamic filtering (By Language / By Category)
 *   - Current editor content transmission to existing compiler
 *   - Multi-tab output console matching desktop gui.py stages
 *   - New file, Open local file, Save As download, Reset to original
 *   - Draggable panel splitters and keyboard shortcuts
 */

(function () {
  "use strict";

  function sha256Bytes(bytes) {
    function rightRotate(value, amount) {
      return (value >>> amount) | (value << (32 - amount));
    }
    var mathPow = Math.pow;
    var maxWord = mathPow(2, 32);
    var i, j;
    var result = '';
    var words = [];
    var bitLength = bytes.length * 8;
    var hash = [];
    var k = [];
    var primeCounter = 0;
    var isComposite = {};
    for (var candidate = 2; primeCounter < 64; candidate++) {
      if (!isComposite[candidate]) {
        for (i = 0; i < 313; i += candidate) {
          isComposite[i] = candidate;
        }
        hash[primeCounter] = (mathPow(candidate, .5) * maxWord) | 0;
        k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
      }
    }
    for (i = 0; i < bytes.length; i++) {
      words[i >> 2] |= bytes[i] << ((3 - i % 4) * 8);
    }
    words[bytes.length >> 2] |= 0x80 << ((3 - bytes.length % 4) * 8);
    var wordCount = ((bytes.length + 8) >> 6) + 1;
    while (words.length < wordCount * 16 - 2) words.push(0);
    words.push((bitLength / maxWord) | 0);
    words.push(bitLength | 0);
    for (j = 0; j < words.length;) {
      var w = words.slice(j, j += 16);
      var oldHash = hash.slice();
      for (i = 0; i < 64; i++) {
        var w15 = w[i - 15], w2 = w[i - 2];
        var s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
        var s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
        w[i] = (i < 16) ? (w[i] | 0) : ((w[i - 16] + s0 + w[i - 7] + s1) | 0);
        var ch = (hash[4] & hash[5]) ^ (~hash[4] & hash[6]);
        var maj = (hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]);
        var temp1 = (hash[7] + (rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25)) + ch + k[i] + w[i]) | 0;
        var temp2 = ((rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22)) + maj) | 0;
        hash = [(temp1 + temp2) | 0].concat(hash);
        hash[4] = (hash[4] + temp1) | 0;
        hash.pop();
      }
      for (i = 0; i < 8; i++) {
        hash[i] = (hash[i] + oldHash[i]) | 0;
      }
    }
    for (i = 0; i < 8; i++) {
      for (j = 3; j >= 0; j--) {
        var b = (hash[i] >> (j * 8)) & 255;
        result += ((b < 16) ? '0' : '') + b.toString(16);
      }
    }
    return result;
  }

  function sha256Sync(str) {
    if (!str) return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    if (typeof TextEncoder !== "undefined") {
      return sha256Bytes(new TextEncoder().encode(str));
    }
    if (typeof Buffer !== "undefined") {
      return sha256Bytes(Buffer.from(str, "utf8"));
    }
    var utf8 = unescape(encodeURIComponent(str));
    var arr = new Uint8Array(utf8.length);
    for (var i = 0; i < utf8.length; i++) arr[i] = utf8.charCodeAt(i);
    return sha256Bytes(arr);
  }

  async function revisionOf(source) {
    const normalized = source.replace(/^\uFEFF/, "").replace(/\r\n?/g, "\n").normalize("NFC");
    if (typeof crypto !== "undefined" && crypto.subtle) {
      const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(normalized));
      return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, "0")).join("").slice(0, 12);
    }
    return sha256Sync(normalized).slice(0, 12);
  }

  async function sourceRequest(url, options) {
    const data = JSON.parse(options.body);
    const source = state.editor.getValue();
    const file = state.currentFile.path;
    const revision = await revisionOf(source);
    Object.assign(data, { source, file_id: file, revision_id: revision, language: state.currentFile.language });
    const response = await fetch(url, { ...options, body: JSON.stringify(data) });
    function checkRevision() {
      if (response.headers.get("X-Source-Revision") !== revision ||
        file !== state.currentFile.path || source !== state.editor.getValue()) {
        throw new Error("Editor changed. Run again to refresh the result.");
      }
    }
    checkRevision();
    return {
      ok: response.ok, status: response.status, body: response.body, json: async () => {
        const body = await response.json();
        checkRevision();
        return body;
      }
    };
  }

  const FIX_ENABLED_CATEGORIES = ["security_lab", "user_code"];

  function isFixEnabledForCurrentFile() {
    if (!state.currentFile) return true;
    if (state.currentFile.is_security_lab) return true;
    const cat = (state.currentFile.category || "").toLowerCase();
    if (cat.includes("security_lab") || cat.includes("user_code")) return true;
    if (state.currentFile.is_user_code || state.currentFile.isDirty || state.isDirty) return true;
    const totalIssues = (state.pipeline && state.pipeline.issues) ? state.pipeline.issues.length : 0;
    const healthIssues = (state.codeHealth && state.codeHealth.total_fixable) ? state.codeHealth.total_fixable : 0;
    if (totalIssues > 0 || healthIssues > 0) return true;
    const path = (state.currentFile.path || "").replace(/\\/g, "/").toLowerCase();
    if (path.includes("security_lab")) return true;
    if (path.startsWith("examples/")) return false;
    return true;
  }

  function updateAiFixRerunButtonVisibility(status) {
    if (!elements || !elements.btnPipelineAiFixRerun) return;
    const norm = String(status || "").toLowerCase();
    const isFailedOrBlocked = norm.includes("fail") || norm.includes("block") || norm.includes("pause");
    if (isFailedOrBlocked && isFixEnabledForCurrentFile()) {
      elements.btnPipelineAiFixRerun.style.display = "inline-flex";
    } else {
      elements.btnPipelineAiFixRerun.style.display = "none";
      if (elements.btnPipelineAiFixStop) {
        elements.btnPipelineAiFixStop.style.display = "none";
      }
    }
  }

  // Application State
  const state = {
    editor: null,
    currentFile: {
      path: "examples/english/hello.vital",
      filename: "hello.vital",
      language: "English",
      title: "Hello World & Variables",
      originalCode: ""
    },
    demosData: null,
    currentExplorerView: "lang", // 'lang' or 'folder'
    expandedGroups: new Set(),
    searchQuery: "",
    isExecuting: false,
    sourceRevisionId: 1,
    runCounter: 0,
    currentBufferHash: "",
    // Requirement 1: Run-scoped security results: { [stageId]: { run_id, source_hash, stage, findings, created_at } }
    securityResults: {},

    // Explicit 14 Logical Compiler Stages (Compiler Design Syllabus Order)
    pipeline: {
      activeRunId: null,
      activeRunSeq: 0,
      lastCompletedRunId: null,
      hasReceivedEventForRun: false,
      isPaused: false,
      pausedStage: null,
      isReadyForReport: false,
      isReportGenerated: false,
      pendingArtifacts: null,
      compiledSource: "",
      compiledSourceVersion: 0,
      stages: [
        { id: "source_input", name: "1. Source Input", desc: "Source Input & Language Detection", icon: "📄", category: "frontend" },
        { id: "lexical_analysis", name: "2. Lexer (Lexical)", desc: "Lexer / Lexical Analysis & Token Stream", icon: "🔤", category: "frontend" },
        { id: "syntax_analysis", name: "3. Parser (Syntax)", desc: "Parser / Syntax Analysis & Grammar Delimiters", icon: "🌲", category: "frontend" },
        { id: "ast_construction", name: "4. AST Construction", desc: "Abstract Syntax Tree (AST) Generation", icon: "🌳", category: "frontend" },
        { id: "semantic_analysis", name: "5. Semantic Analysis", desc: "Context-Sensitive Semantic Analysis", icon: "🔍", category: "frontend" },
        { id: "symbol_table", name: "6. Symbol Table", desc: "Symbol Table & Scope Resolution", icon: "📋", category: "frontend" },
        { id: "ir_generation", name: "7. Intermediate Rep (IR)", desc: "Intermediate Representation (Transpilation)", icon: "⚙️", category: "middle-end" },
        { id: "optimization", name: "8. Optimization", desc: "Mandatory IR Optimization (Constant Folding & Dead Code Elimination)", icon: "⚡", category: "middle-end", unavailable: false },
        { id: "code_generation", name: "9. Code Generation", desc: "Target Code Generation", icon: "🐍", category: "backend" },
        { id: "code_validation", name: "10. Target Validation", desc: "Generated-Code AST Validation", icon: "✅", category: "backend" },
        { id: "security_analysis", name: "11. Security Analysis", desc: "Deterministic Static Security Scan", icon: "🛡️", category: "security" },
        { id: "ai_security_analysis", name: "12. AI Security Analysis", desc: "Gemini AI Security Agent", icon: "🤖", category: "security" },
        { id: "sandbox_execution", name: "13. Sandbox Execution", desc: "Subprocess Sandboxed Execution", icon: "▶️", category: "backend" },
        { id: "final_report", name: "14. Final Report", desc: "Final Report & Metrics Assembly", icon: "📊", category: "backend" }
      ],
      stageData: {},
      activeDrawerStage: null
    },
    security: {
      findings: [],
      overallScore: 0,
      aiStatus: { online: false, model: "gemini-flash-lite-latest" },
      ollamaStatus: { online: false, model: "gemini-flash-lite-latest" },
      undoStack: [],
      pendingFix: null
    },
    // Per-file working buffer store: preserves editor state, cursor, and undo history across demo switches
    fileStore: {},
    issuesCache: {},
    sessionId: (typeof sessionStorage !== "undefined" && sessionStorage.getItem("vital_session_id")) || ("sess-" + Date.now() + "-" + Math.random().toString(36).substring(2, 10))
  };

  // DOM Elements
  const elements = {
    editorTextarea: document.getElementById("code-editor"),
    btnRun: document.getElementById("btn-run"),
    btnCancelRun: document.getElementById("btn-cancel-run"),
    runBtnIcon: document.getElementById("run-btn-icon"),
    runBtnText: document.getElementById("run-btn-text"),
    toggleStage12Ai: document.getElementById("toggle-stage12-ai"),
    btnNew: document.getElementById("btn-new"),
    btnExportReportHtml: document.getElementById("btn-export-report-html"),
    btnExportReportJson: document.getElementById("btn-export-report-json"),

    // Header badges
    currentLangTag: document.getElementById("current-lang-tag"),
    currentFilenameText: document.getElementById("current-filename-text"),

    // Editor tab & breadcrumb
    tabFilename: document.getElementById("tab-filename"),
    tabDirtyIndicator: document.getElementById("tab-dirty-indicator"),
    breadcrumbLang: document.getElementById("breadcrumb-lang"),
    breadcrumbPath: document.getElementById("breadcrumb-path"),

    // Explorer
    tabViewLang: document.getElementById("tab-view-lang"),
    tabViewFolder: document.getElementById("tab-view-folder"),
    demoSearchInput: document.getElementById("demo-search-input"),
    demoTree: document.getElementById("demo-tree"),
    totalDemosCount: document.getElementById("total-demos-count"),

    // Output
    outputWaitingState: document.getElementById("output-waiting-state"),
    outputWaitingMessage: document.getElementById("output-waiting-message"),
    outputWaitingSubtext: document.getElementById("output-waiting-subtext"),
    outputTabsBar: document.getElementById("output-tabs-bar"),
    outputContentArea: document.getElementById("output-content-area"),
    outputTabBtns: document.querySelectorAll(".output-tab-btn"),
    outputTimingBadge: document.getElementById("output-timing-badge"),
    btnCopyOutput: document.getElementById("btn-copy-output"),
    consoleProgram: document.getElementById("console-program-output"),
    consolePipeline: document.getElementById("console-pipeline-report"),
    consoleLexer: document.getElementById("console-lexer-log"),
    consoleParser: document.getElementById("console-parser-log"),
    consoleAst: document.getElementById("console-ast-log"),
    consoleIr: document.getElementById("console-ir-code"),
    consoleSymbol: document.getElementById("console-symbol-table"),
    consoleOptimization: document.getElementById("console-optimization-report"),
    outputBlockedEmptyState: document.getElementById("output-blocked-empty-state"),
    outputBlockedTitle: document.getElementById("output-blocked-title"),
    outputBlockedReason: document.getElementById("output-blocked-reason"),
    btnJumpBlockedFindings: document.getElementById("btn-jump-blocked-findings"),
    btnJumpCodeHealth: document.getElementById("btn-jump-code-health"),
    btnBlockedOverrideRun: document.getElementById("btn-blocked-override-run"),
    pipelineReportIncompleteBanner: document.getElementById("pipeline-report-incomplete-banner"),
    btnPipelineSaveCorrected: document.getElementById("btn-pipeline-save-corrected"),

    // Code Health Elements
    editorHealthChip: document.getElementById("editor-health-chip"),
    healthChipSummary: document.getElementById("health-chip-summary"),
    healthChipDetails: document.getElementById("health-chip-details"),
    tabBtnHealth: document.getElementById("tab-btn-health"),
    tabOutHealth: document.getElementById("tab-out-health"),
    btnHealthRefresh: document.getElementById("btn-health-refresh"),
    btnHealthRetry: document.getElementById("btn-health-retry"),
    healthAccuracyBadge: document.getElementById("health-accuracy-badge"),
    btnHealthFixAll: document.getElementById("btn-health-fix-all"),
    healthFixDelta: document.getElementById("health-fix-delta"),
    healthFixDeltaText: document.getElementById("health-fix-delta-text"),
    fixModalSuspectWarning: document.getElementById("fix-modal-suspect-warning"),
    fixModalSuspectText: document.getElementById("fix-modal-suspect-text"),

    // Pipeline Preflight Strip
    pipelinePreflightStrip: document.getElementById("pipeline-preflight-strip"),
    pipelinePreflightMessage: document.getElementById("pipeline-preflight-message"),
    pipelinePreflightAccuracy: document.getElementById("pipeline-preflight-accuracy"),


    // Section 11: Pipeline Progress Elements
    pipelineProgressContainer: document.getElementById("pipeline-progress-container"),
    pipelineStepper: document.getElementById("pipeline-stepper"),
    pipelineStatusBadge: document.getElementById("pipeline-status-badge"),
    pipelineMetricStage: document.getElementById("pipeline-metric-stage"),
    pipelineMetricProgress: document.getElementById("pipeline-metric-progress"),
    pipelineMetricTime: document.getElementById("pipeline-metric-time"),
    pipelineProgressFill: document.getElementById("pipeline-progress-fill"),
    pipelineStageDrawer: document.getElementById("stage-overlay-backdrop") || document.getElementById("pipeline-stage-drawer"),
    stageOverlayBackdrop: document.getElementById("stage-overlay-backdrop") || document.getElementById("pipeline-stage-drawer"),
    stageOverlayDialog: document.getElementById("stage-overlay-dialog"),
    drawerStageTitle: document.getElementById("drawer-stage-title"),
    drawerStageBody: document.getElementById("drawer-stage-body"),
    drawerCloseBtn: document.getElementById("drawer-close-btn"),

    // Security Dashboard Elements
    tabBtnSecurity: document.getElementById("tab-btn-security"),
    securityTabRiskPill: document.getElementById("security-tab-risk-pill"),
    securityScoreCircle: document.getElementById("security-score-circle"),
    securityScoreVal: document.getElementById("security-score-val"),
    securityVerdict: document.getElementById("security-verdict"),
    securitySubtext: document.getElementById("security-subtext"),
    pillCountCrit: document.getElementById("pill-count-crit"),
    pillCountHigh: document.getElementById("pill-count-high"),
    pillCountMed: document.getElementById("pill-count-med"),
    pillCountLow: document.getElementById("pill-count-low"),
    aiStatusIndicator: document.getElementById("ai-status-indicator") || document.getElementById("ollama-status-indicator"),
    aiPulseDot: document.getElementById("ai-pulse-dot") || document.getElementById("ollama-pulse-dot"),
    aiStatusLabel: document.getElementById("ai-status-label") || document.getElementById("ollama-status-label"),
    ollamaStatusIndicator: document.getElementById("ai-status-indicator") || document.getElementById("ollama-status-indicator"),
    ollamaPulseDot: document.getElementById("ai-pulse-dot") || document.getElementById("ollama-pulse-dot"),
    ollamaStatusLabel: document.getElementById("ai-status-label") || document.getElementById("ollama-status-label"),
    btnScanSecurity: document.getElementById("btn-scan-security"),
    btnUndoFix: document.getElementById("btn-undo-editor-fix") || document.getElementById("btn-undo-fix"),
    securityEmptyState: document.getElementById("security-empty-state"),
    securityFindingsList: document.getElementById("security-findings-list"),

    // Editor Action Buttons
    btnViewOriginal: document.getElementById("btn-view-original"),
    btnRestoreOriginal: document.getElementById("btn-restore-original"),
    btnUndoEditorFix: document.getElementById("btn-undo-editor-fix"),

    // Diff & Fix Review Modal Elements
    fixModalOverlay: document.getElementById("fix-modal-overlay"),
    fixModalCard: document.querySelector(".fix-modal-card"),
    fixModalPerErrorContainer: document.getElementById("fix-modal-per-error-container"),
    fixModalTitle: document.getElementById("fix-modal-title"),
    fixModalSeverity: document.getElementById("fix-modal-severity"),
    fixModalSource: document.getElementById("fix-modal-source"),
    fixModalValidation: document.getElementById("fix-modal-validation"),
    fixAiRefiningBar: document.getElementById("fix-ai-refining-bar"),
    fixAiRefiningText: document.getElementById("fix-ai-refining-text"),
    fixModalExplanation: document.getElementById("fix-modal-explanation"),
    btnModeUnified: document.getElementById("btn-mode-unified"),
    btnModeSplit: document.getElementById("btn-mode-split"),
    diffContainerUnified: document.getElementById("diff-container-unified"),
    diffContainerSplit: document.getElementById("diff-container-split"),
    fixDiffPreview: document.getElementById("fix-diff-preview"),
    fixSplitBefore: document.getElementById("fix-split-before"),
    fixSplitAfter: document.getElementById("fix-split-after"),
    btnCloseFixModal: document.getElementById("btn-close-fix-modal"),
    btnRejectFix: document.getElementById("btn-reject-fix"),
    btnModalViewOriginal: document.getElementById("btn-modal-view-original"),
    btnModalUndoFix: document.getElementById("btn-modal-undo-fix"),
    btnApplyFix: document.getElementById("btn-apply-fix"),

    // Dedicated Original Demo Viewer Modal Elements
    originalModalOverlay: document.getElementById("original-modal-overlay"),
    originalModalPath: document.getElementById("original-modal-path"),
    originalModalCode: document.getElementById("original-modal-code"),
    btnCloseOriginalModal: document.getElementById("btn-close-original-modal"),
    btnDismissOriginalModal: document.getElementById("btn-dismiss-original-modal"),
    btnModalRestoreIntoBuffer: document.getElementById("btn-modal-restore-into-buffer"),

    // Status bar
    ideStatusbar: document.getElementById("ide-statusbar"),
    statusIndicatorDot: document.getElementById("status-indicator-dot"),
    statusbarText: document.getElementById("statusbar-text"),
    statusbarElapsed: document.getElementById("statusbar-elapsed"),
    statusbarCursor: document.getElementById("statusbar-cursor"),

    // Resizers
    panelExplorer: document.getElementById("panel-explorer"),

    // AI Fix & Re-run Header & Modal Elements
    btnPipelineAiFixRerun: document.getElementById("btn-pipeline-ai-fix-rerun"),
    btnPipelineAiFixStop: document.getElementById("btn-pipeline-ai-fix-stop"),
    pipelineAiFixRerunText: document.getElementById("pipeline-ai-fix-rerun-text"),
    aiFixRerunModalOverlay: document.getElementById("ai-fix-rerun-modal-overlay"),
    aiFixRerunModalTitle: document.getElementById("ai-fix-rerun-modal-title"),
    aiFixRerunStatusBadge: document.getElementById("ai-fix-rerun-status-badge"),
    aiFixRerunIterationLogs: document.getElementById("ai-fix-rerun-iteration-logs"),
    aiFixRerunSummarySection: document.getElementById("ai-fix-rerun-summary-section"),
    aiFixRerunStatsPills: document.getElementById("ai-fix-rerun-stats-pills"),
    aiFixRerunSuspectBanner: document.getElementById("ai-fix-rerun-suspect-banner"),
    aiFixRerunDiffPre: document.getElementById("ai-fix-rerun-diff-pre"),
    btnAiFixRerunUndo: document.getElementById("btn-ai-fix-rerun-undo"),
    btnAiFixRerunSave: document.getElementById("btn-ai-fix-rerun-save"),
    btnAiFixRerunClose: document.getElementById("btn-ai-fix-rerun-close"),
    btnCloseAiFixRerunModal: document.getElementById("btn-close-ai-fix-rerun-modal"),
    panelOutput: document.getElementById("panel-output"),
    resizerLeft: document.getElementById("resizer-left"),
    resizerRight: document.getElementById("resizer-right")
  };

  /* ========================================================================
     0. WORKING BUFFER STORAGE & PERSISTENCE
     ======================================================================== */
  const BUFFER_STORAGE_KEY = "vital_ide_working_buffers_v2";

  function loadWorkingBuffersFromStorage() {
    try {
      const raw = localStorage.getItem(BUFFER_STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === "object") {
          state.fileStore = parsed;
        }
      }
    } catch (e) {
      console.warn("Could not load working buffers from localStorage:", e);
    }
  }

  function persistWorkingBuffersToStorage() {
    try {
      const serialized = JSON.stringify(state.fileStore);
      localStorage.setItem(BUFFER_STORAGE_KEY, serialized);
    } catch (e) {
      console.warn("Could not persist working buffers to localStorage:", e);
    }
  }

  function saveCurrentFileBuffer() {
    if (!state.currentFile || !state.currentFile.path || !state.editor) return;
    const currentPath = state.currentFile.path;
    const currentVal = state.editor.getValue();
    const cursor = state.editor.getCursor();

    if (!state.fileStore[currentPath]) {
      state.fileStore[currentPath] = {
        path: currentPath,
        filename: state.currentFile.filename,
        language: state.currentFile.language,
        title: state.currentFile.title,
        originalCode: state.currentFile.originalCode
      };
    }

    state.fileStore[currentPath].workingBuffer = currentVal;
    state.fileStore[currentPath].cursor = cursor;
    state.fileStore[currentPath].undoStack = (state.security.undoStack || []).slice();
    state.fileStore[currentPath].isDirty = (currentVal !== state.fileStore[currentPath].originalCode);
    persistWorkingBuffersToStorage();
  }

  /* ========================================================================
     1. INITIALIZATION
     ======================================================================== */
  function init() {
    try {
      localStorage.removeItem("vital_ide_theme");
      localStorage.removeItem("theme");
    } catch (e) {
      // Ignore storage errors in restricted contexts
    }
    loadWorkingBuffersFromStorage();
    initCodeMirror();
    bindEvents();
    bindSecurityEvents();
    setupResizers();
    loadDemosList();
    initPipelineStepper();
    checkAIStatus();
  }

  function initCodeMirror() {
    state.editor = CodeMirror.fromTextArea(elements.editorTextarea, {
      mode: "vital",
      lineNumbers: true,
      matchBrackets: true,
      autoCloseBrackets: true,
      styleActiveLine: true,
      gutters: ["CodeMirror-linenumbers", "health-gutter-markers"],
      indentUnit: 4,
      tabSize: 4,
      indentWithTabs: false,
      lineWrapping: true,
      extraKeys: {
        "Ctrl-Enter": function () { runCompiler(); },
        "Cmd-Enter": function () { runCompiler(); },
        "Tab": function (cm) {
          if (cm.somethingSelected()) {
            cm.indentSelection("add");
          } else {
            cm.replaceSelection("    ", "end");
          }
        }
      }
    });

    // Track Cursor position
    state.editor.on("cursorActivity", function () {
      const pos = state.editor.getCursor();
      elements.statusbarCursor.textContent = `Ln ${pos.line + 1}, Col ${pos.ch + 1}`;
    });

    // Track modifications / dirty state and trigger debounced real-time AI assistance
    state.editor.on("change", function () {
      const currentVal = state.editor.getValue();
      const isDirty = updateTabModifiedIndicator();

      // Synchronize in-memory working buffer for current file
      if (state.currentFile && state.currentFile.path) {
        if (!state.fileStore[state.currentFile.path]) {
          state.fileStore[state.currentFile.path] = {
            path: state.currentFile.path,
            filename: state.currentFile.filename,
            language: state.currentFile.language,
            title: state.currentFile.title,
            originalCode: state.currentFile.originalCode,
            workingBuffer: currentVal,
            isDirty: isDirty
          };
        } else {
          state.fileStore[state.currentFile.path].workingBuffer = currentVal;
          state.fileStore[state.currentFile.path].isDirty = isDirty;
        }
      }

      // Requirement 1: Reset pipeline state and update save status on any edit
      resetPipelineFullState("buffer_edit");
      updateSaveButtonState();

      showOutputWaitingState(
        "Source Modified — Re-compilation Needed",
        "Editor working buffer has changed. Click 'Run' to execute the sequential compiler pipeline on the new source."
      );

      // Trigger debounced pre-run Code Health analysis (600 ms)
      state.issuesCache = {};
      setFixAllButtonState("loading");
      scheduleHealthAnalysis(600, true);
    });
  }

  /* ========================================================================
     2. EVENT BINDINGS
     ======================================================================== */
  function bindEvents() {
    // Stage 12 AI Toggle (Task A.2: default OFF, persist in localStorage)
    if (elements.toggleStage12Ai) {
      const savedToggle = localStorage.getItem("vital_stage12_ai_enabled");
      elements.toggleStage12Ai.checked = savedToggle === "true";
      elements.toggleStage12Ai.addEventListener("change", () => {
        localStorage.setItem("vital_stage12_ai_enabled", elements.toggleStage12Ai.checked ? "true" : "false");
      });
    }

    // Run Button
    elements.btnRun.addEventListener("click", () => runCompiler());

    // Cancel Button (Requirement 2)
    if (elements.btnCancelRun) {
      elements.btnCancelRun.addEventListener("click", () => cancelActivePipelineRun());
    }

    const btnOverride = document.getElementById("btn-security-override-run");
    if (btnOverride) {
      btnOverride.addEventListener("click", () => {
        if (confirm("WARNING: This code contains security vulnerabilities detected by SAST/AI.\n\nExecuting this code will run it in an isolated sandbox with a 5-second timeout, but execution could be dangerous or produce unexpected behavior.\n\nDo you want to proceed with SECURITY OVERRIDE?")) {
          runCompiler(null, false, true);
        }
      });
    }

    const btnBlockedOverride = document.getElementById("btn-blocked-override-run");
    if (btnBlockedOverride) {
      btnBlockedOverride.addEventListener("click", () => {
        if (confirm("WARNING: This code contains security vulnerabilities detected by SAST/AI.\n\nExecuting this code will run it in an isolated sandbox with a 5-second timeout, but execution could be dangerous or produce unexpected behavior.\n\nDo you want to proceed with SECURITY OVERRIDE?")) {
          runCompiler(null, false, true);
        }
      });
    }

    const btnJumpBlocked = document.getElementById("btn-jump-blocked-findings");
    if (btnJumpBlocked) {
      btnJumpBlocked.addEventListener("click", () => {
        const targetStage = state.pipeline.blockingStageId || state.pipeline.pausedStage || "security_analysis";
        openStageDrawer(targetStage);
      });
    }

    const btnJumpHealth = document.getElementById("btn-jump-code-health");
    if (btnJumpHealth) {
      btnJumpHealth.addEventListener("click", () => {
        openStageDrawer("security_analysis");
      });
    }

    // New File
    elements.btnNew.addEventListener("click", createNewFile);


    // Explicit Working Buffer & Original Source Actions
    if (elements.btnViewOriginal) {
      elements.btnViewOriginal.addEventListener("click", openOriginalViewModal);
    }
    if (elements.btnRestoreOriginal) {
      elements.btnRestoreOriginal.addEventListener("click", restoreOriginalDemo);
    }
    if (elements.btnUndoEditorFix) {
      elements.btnUndoEditorFix.addEventListener("click", undoLastSecurityFix);
    }

    if (elements.btnHealthFixAll) {
      elements.btnHealthFixAll.addEventListener("click", handleStageTargetedFixAll);
    }

    const pipeSaveBtn = document.getElementById("btn-pipeline-save-corrected");
    if (pipeSaveBtn) {
      pipeSaveBtn.addEventListener("click", saveCorrectedCode);
    }
    const pipeRestoreBtn = document.getElementById("btn-pipeline-restore-original");
    if (pipeRestoreBtn) {
      pipeRestoreBtn.addEventListener("click", restoreOriginalDemo);
    }

    if (elements.btnExportReportHtml) {
      elements.btnExportReportHtml.addEventListener("click", exportReportHtml);
    }
    if (elements.btnExportReportJson) {
      elements.btnExportReportJson.addEventListener("click", exportReportJson);
    }

    // Modal View Mode Toggles (Unified vs Split)
    if (elements.btnModeUnified) {
      elements.btnModeUnified.addEventListener("click", () => switchDiffViewMode("unified"));
    }
    if (elements.btnModeSplit) {
      elements.btnModeSplit.addEventListener("click", () => switchDiffViewMode("split"));
    }
    if (elements.btnModalViewOriginal) {
      elements.btnModalViewOriginal.addEventListener("click", openOriginalViewModal);
    }
    if (elements.btnModalUndoFix) {
      elements.btnModalUndoFix.addEventListener("click", () => {
        undoLastSecurityFix();
        closeFixModal();
      });
    }

    // Dedicated Original Viewer Modal Actions
    if (elements.btnCloseOriginalModal) {
      elements.btnCloseOriginalModal.addEventListener("click", closeOriginalViewModal);
    }
    if (elements.btnDismissOriginalModal) {
      elements.btnDismissOriginalModal.addEventListener("click", closeOriginalViewModal);
    }
    if (elements.btnModalRestoreIntoBuffer) {
      elements.btnModalRestoreIntoBuffer.addEventListener("click", restoreOriginalDemo);
    }

    // Stage Details Floating Overlay outside click & Escape dismiss
    if (elements.stageOverlayBackdrop) {
      elements.stageOverlayBackdrop.addEventListener("click", (e) => {
        if (e.target === elements.stageOverlayBackdrop) {
          closeStageDrawer();
        }
      });
    }
    if (elements.stageOverlayDialog) {
      elements.stageOverlayDialog.addEventListener("click", (e) => {
        e.stopPropagation();
      });
    }

    if (elements.btnPipelineAiFixRerun) {
      elements.btnPipelineAiFixRerun.addEventListener("click", startAiFixAndRerunLoop);
    }
    if (elements.btnPipelineAiFixStop) {
      elements.btnPipelineAiFixStop.addEventListener("click", () => {
        if (aiFixRerunAbortController) {
          aiFixRerunAbortController.abort();
        }
      });
    }
    if (elements.btnCloseAiFixRerunModal) {
      elements.btnCloseAiFixRerunModal.addEventListener("click", closeAiFixRerunModal);
    }
    if (elements.btnAiFixRerunClose) {
      elements.btnAiFixRerunClose.addEventListener("click", closeAiFixRerunModal);
    }

    // Global Escape Key to close overlay or modals
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" || e.keyCode === 27) {
        if (elements.aiFixRerunModalOverlay && elements.aiFixRerunModalOverlay.style.display !== "none") {
          closeAiFixRerunModal();
        } else if (state.pipeline && state.pipeline.activeDrawerStage) {
          closeStageDrawer();
        } else if (elements.fixModalOverlay && elements.fixModalOverlay.style.display !== "none") {
          closeFixModal();
        } else if (elements.originalModalOverlay && elements.originalModalOverlay.style.display !== "none") {
          closeOriginalViewModal();
        }
      }
    });

    // Window Unload Protection: persist working buffer to storage
    window.addEventListener("beforeunload", () => {
      saveCurrentFileBuffer();
    });


    // Explorer view tabs
    elements.tabViewLang.addEventListener("click", () => switchExplorerView("lang"));
    elements.tabViewFolder.addEventListener("click", () => switchExplorerView("folder"));

    // Search input
    elements.demoSearchInput.addEventListener("input", (e) => {
      state.searchQuery = e.target.value.toLowerCase().trim();
      renderExplorerTree();
    });

    // Output Stage Tabs
    elements.outputTabBtns.forEach(btn => {
      btn.addEventListener("click", () => {
        const targetId = btn.getAttribute("data-tab");
        switchOutputTab(targetId);
      });
    });

    // Copy Output Button
    elements.btnCopyOutput.addEventListener("click", copyActiveOutput);

    // Code Health Chip Click & Accessibility
    if (elements.editorHealthChip) {
      elements.editorHealthChip.addEventListener("click", () => {
        switchOutputTab("tab-out-health");
      });
      elements.editorHealthChip.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          switchOutputTab("tab-out-health");
        }
      });
    }

    if (elements.btnHealthRefresh) {
      elements.btnHealthRefresh.addEventListener("click", () => {
        runHealthAnalysis(true);
      });
    }

    if (elements.btnHealthRetry) {
      elements.btnHealthRetry.addEventListener("click", () => {
        runHealthAnalysis(true);
      });
    }

    if (elements.btnJumpCodeHealth) {
      elements.btnJumpCodeHealth.addEventListener("click", () => {
        switchOutputTab("tab-out-health");
      });
    }

  }

  /* ========================================================================
     3. DEMO DISCOVERY & EXPLORER
     ======================================================================== */
  async function loadDemosList() {
    try {
      setStatus("Loading available demo programs...", "info");
      const resp = await fetch("/api/demos");
      const json = await resp.json();

      if (json.success && json.data) {
        state.demosData = json.data;
        elements.totalDemosCount.textContent = `${json.data.total_count} Demos`;
        renderExplorerTree();

        // Load initial demo (query param or default)
        const urlParams = new URLSearchParams(window.location.search);
        const fileParam = urlParams.get("file");
        const defaultPath = fileParam || "examples/english/hello.vital";
        await loadDemoFile(defaultPath);
        setStatus("System Ready | Multilingual Engine Loaded", "ready");
        await recoverRunAfterRefresh();
      } else {
        setStatus("Error loading demos list", "error");
      }
    } catch (err) {
      console.error("Demos list load error:", err);
      setStatus("Failed to connect to backend", "error");
    }
  }

  function switchExplorerView(view) {
    state.currentExplorerView = view;
    // Reset expanded groups when changing view tab so groups start inside
    if (state.expandedGroups) {
      state.expandedGroups.clear();
    }
    if (view === "lang") {
      elements.tabViewLang.classList.add("active");
      elements.tabViewFolder.classList.remove("active");
    } else {
      elements.tabViewFolder.classList.add("active");
      elements.tabViewLang.classList.remove("active");
    }
    renderExplorerTree();
  }

  function renderExplorerTree() {
    if (!state.demosData) return;
    elements.demoTree.innerHTML = "";

    const isLangView = (state.currentExplorerView === "lang");
    const groups = isLangView ? state.demosData.by_language : state.demosData.by_category;
    const groupKeys = isLangView ? state.demosData.languages_order : state.demosData.categories_order;

    let hasMatches = false;
    const isSearching = Boolean(state.searchQuery && state.searchQuery.trim().length > 0);

    groupKeys.forEach(groupName => {
      const items = groups[groupName] || [];
      // Filter by search query
      const filtered = items.filter(item => {
        if (!state.searchQuery) return true;
        const q = state.searchQuery;
        return item.filename.toLowerCase().includes(q) ||
          item.title.toLowerCase().includes(q) ||
          item.language.toLowerCase().includes(q) ||
          item.path.toLowerCase().includes(q);
      });

      if (filtered.length === 0) return;
      hasMatches = true;

      // Group is expanded ONLY if the user explicitly clicked to open it, or if actively searching.
      // Normally, all sample groups stay collapsed inside until clicked.
      const isExpanded = isSearching || (state.expandedGroups && state.expandedGroups.has(groupName));

      // Create group section
      const section = document.createElement("div");
      section.className = isExpanded ? "tree-section" : "tree-section collapsed";

      // Group Header
      const header = document.createElement("div");
      header.className = "tree-section-header";

      const leftDiv = document.createElement("div");
      leftDiv.className = "tree-section-left";
      leftDiv.innerHTML = `<span class="tree-arrow">▼</span><span>${groupName}</span>`;

      const badge = document.createElement("span");
      badge.className = "tree-count-badge";
      badge.textContent = filtered.length;

      header.appendChild(leftDiv);
      header.appendChild(badge);

      header.addEventListener("click", () => {
        const wasCollapsed = section.classList.contains("collapsed");
        section.classList.toggle("collapsed");
        if (state.expandedGroups) {
          if (wasCollapsed) {
            state.expandedGroups.add(groupName);
          } else {
            state.expandedGroups.delete(groupName);
          }
        }
      });

      // Group Items List
      const list = document.createElement("div");
      list.className = "tree-items-list";

      filtered.forEach(item => {
        const fileItem = document.createElement("div");
        fileItem.className = "tree-file-item";
        if (state.currentFile.path === item.path) {
          fileItem.classList.add("active");
        }

        const titleSpan = document.createElement("span");
        titleSpan.className = "tree-file-title";
        titleSpan.textContent = item.filename;
        titleSpan.title = `${item.title} (${item.path})`;

        const tagSpan = document.createElement("span");
        tagSpan.className = "tree-file-tag";
        tagSpan.textContent = isLangView ? item.category.replace("Benchmark: ", "").replace("Examples", "") : item.language;

        fileItem.appendChild(titleSpan);
        if (item.is_security_lab) {
          const secBadge = document.createElement("span");
          secBadge.className = `tree-sec-badge diff-badge-${(item.difficulty || "medium").toLowerCase()}`;
          secBadge.textContent = item.difficulty || "Lab";
          secBadge.title = `Security Lab: ${item.scenario_type || 'Educational Faulty Demo'}`;
          fileItem.appendChild(secBadge);
        }
        fileItem.appendChild(tagSpan);

        fileItem.addEventListener("click", () => {
          loadDemoFile(item.path);
        });

        list.appendChild(fileItem);
      });

      section.appendChild(header);
      section.appendChild(list);
      elements.demoTree.appendChild(section);
    });

    if (!hasMatches) {
      elements.demoTree.innerHTML = `
        <div style="padding: 16px; color: var(--text-dim); text-align: center;">
          No matching demo programs found.
        </div>
      `;
    }
  }

  function highlightActiveTreeItem(path, filename) {
    document.querySelectorAll(".tree-file-item").forEach(item => {
      item.classList.remove("active");
      const title = item.querySelector(".tree-file-title");
      if (title && title.textContent === filename && title.title && title.title.includes(path)) {
        item.classList.add("active");
      }
    });
  }

  function setupSecurityBanner(metaObj) {
    let banner = document.getElementById("sec-lab-banner");
    if (metaObj.is_security_lab || metaObj.security_lab_meta) {
      if (!banner) {
        banner = document.createElement("div");
        banner.id = "sec-lab-banner";
        banner.className = "sec-lab-banner";
        const editorWrapper = document.querySelector(".codemirror-wrapper");
        if (editorWrapper && editorWrapper.parentNode) {
          editorWrapper.parentNode.insertBefore(banner, editorWrapper);
        }
      }
      const meta = metaObj.security_lab_meta || {};
      const diff = meta.difficulty || metaObj.difficulty || "Intermediate";
      const scenario = meta.scenario_type || metaObj.scenario_type || metaObj.title || "";
      const defects = (meta.defect_categories || metaObj.defect_categories || []).join(", ");
      banner.innerHTML = `
        <div class="sec-lab-banner-content">
          <span class="sec-lab-banner-tag">🛡️ INTENTIONALLY VULNERABLE — FOR EDUCATIONAL TESTING</span>
          <span class="tree-sec-badge diff-badge-${diff.toLowerCase()}">${escapeHtml(diff)}</span>
          <span class="sec-lab-banner-desc">${escapeHtml(scenario)}</span>
          ${defects ? `<span class="sec-lab-banner-defects">• Seeded: ${escapeHtml(defects)}</span>` : ''}
        </div>
        <button class="btn btn-secondary btn-sm" id="btn-quick-sec-scan" style="font-size: 11px; padding: 2px 8px;">🔍 Run Security Scan</button>
      `;
      banner.style.display = "flex";
      const qScan = document.getElementById("btn-quick-sec-scan");
      if (qScan) {
        qScan.addEventListener("click", () => {
          switchOutputTab("tab-out-security");
          runSecurityScan(true);
        });
      }
      // Note: Never auto-run security scan on file open (Bug A fix).
    } else if (banner) {
      banner.style.display = "none";
    }
  }

  async function loadDemoFile(relPath, forceRestore = false) {
    try {
      // 1. Snapshot previous open file's buffer, cursor, and undo stack
      saveCurrentFileBuffer();

      // 2. Fetch authoritative working copy from backend via /api/demo-content
      if (elements.healthFixDelta) {
        elements.healthFixDelta.style.display = "none";
      }
      setStatus(`Loading ${relPath}...`, "info");
      const resp = await fetch(`/api/demo-content?path=${encodeURIComponent(relPath)}`);
      const json = await resp.json();

      if (json.success) {
        const originalCode = json.original_code || json.code;
        const workingSource = json.code;
        const isModified = Boolean(json.is_modified);

        state.currentFile = {
          path: json.path,
          filename: json.filename,
          language: json.language,
          title: json.title,
          originalCode: originalCode,
          is_security_lab: json.is_security_lab,
          security_lab_meta: json.security_lab_meta
        };

        state.sourceRevisionId = json.source_revision || 1;
        state.contentHash = json.content_hash || "";
        if (state.pipeline) {
          state.pipeline.sourceRevisionId = state.sourceRevisionId;
          state.pipeline.compiledSource = null;
          state.pipeline.isReportGenerated = false;
          state.pipeline.isReadyForReport = false;
          state.pipeline.pendingArtifacts = null;
        }

        // Initialize in fileStore
        state.fileStore[json.path] = {
          path: json.path,
          filename: json.filename,
          language: json.language,
          title: json.title,
          originalCode: originalCode,
          workingBuffer: workingSource,
          cursor: { line: 0, ch: 0 },
          undoStack: [],
          isDirty: isModified,
          source_revision: state.sourceRevisionId,
          content_hash: state.contentHash,
          is_security_lab: json.is_security_lab,
          security_lab_meta: json.security_lab_meta
        };
        persistWorkingBuffersToStorage();

        // Update CodeMirror
        state.editor.setValue(workingSource);
        state.editor.clearHistory();
        // Do not clear the undo stack on working-copy load unless explicit force restore was requested
        state.security.undoStack = [];
        state.findingsStore = {};
        state.findingFixes = {};
        state.issuesCache = {};
        resetPipelineFullState("file_switch");
        showOutputWaitingState(
          "Awaiting Compilation & Final Report",
          "Compiler artifacts will appear here after all required stages pass and the Final Report is generated."
        );
        closeStageDrawer();
        updateUndoButtonsState(json.undo_count > 0);

        // Update UI Badges & Tab Dirty Indicator
        state.currentFile.originalHash = sha256Sync(originalCode || "");
        updateHeaderAndBreadcrumbs();
        updateTabModifiedIndicator();
        updateSaveButtonState();
        runHealthAnalysis(true);

        // Re-highlight active in explorer tree
        highlightActiveTreeItem(json.path, json.filename);

        // Security Lab Educational Banner
        setupSecurityBanner(json);

        // Trigger immediate Code Health analysis on file open
        scheduleHealthAnalysis(0, false);

        let statusMsg = isModified
          ? `Status: Loaded persisted working copy for ${json.filename} (Revision ${state.sourceRevisionId})`
          : `Status: Loaded ${json.filename} (${json.language})`;
        if (json.corrupted_discarded) {
          statusMsg = "Corrupted working copy discarded";
          setStatus(statusMsg, "warning");
        } else {
          setStatus(statusMsg, "ready");
        }
      } else {
        setStatus(`Error: ${json.error}`, "error");
      }
    } catch (err) {
      console.error("Load file error:", err);
      setStatus("Error fetching demo file", "error");
    }
  }

  function updateHeaderAndBreadcrumbs() {
    elements.currentLangTag.textContent = state.currentFile.language;
    elements.currentFilenameText.textContent = state.currentFile.filename;
    elements.tabFilename.textContent = state.currentFile.filename;
    elements.breadcrumbLang.textContent = state.currentFile.language;
    elements.breadcrumbPath.textContent = state.currentFile.path || "Custom File";
  }

  /* ========================================================================
     SECTION 11: LIVE COMPILER PIPELINE PROGRESS TRACKER
     ======================================================================== */
  /* ========================================================================
     SECTION 11: LIVE COMPILER PIPELINE PROGRESS TRACKER (14 CANONICAL STAGES)
     ======================================================================== */
  const STAGE_ALIASES = {
    parser_validation: "syntax_analysis",
    ir_transpilation: "ir_generation",
    deterministic_security: "security_analysis",
    execution_sandbox: "sandbox_execution"
  };

  function showOutputWaitingState(message, subtext, showOverride = false) {
    if (elements.outputWaitingState) elements.outputWaitingState.style.display = "flex";
    if (elements.outputWaitingMessage && message) elements.outputWaitingMessage.textContent = message;
    if (elements.outputWaitingSubtext && subtext) elements.outputWaitingSubtext.textContent = subtext;
    if (elements.outputTabsBar) elements.outputTabsBar.style.display = "flex";
    if (elements.outputContentArea) elements.outputContentArea.style.display = "block";
    const btnOverride = document.getElementById("btn-security-override-run");
    if (btnOverride) {
      btnOverride.style.display = showOverride ? "inline-block" : "none";
    }
  }

  function showOutputArtifacts(artifacts) {
    if (elements.outputWaitingState) elements.outputWaitingState.style.display = "none";
    const btnOverride = document.getElementById("btn-security-override-run");
    if (btnOverride) btnOverride.style.display = "none";
    const emptyState = document.getElementById("output-blocked-empty-state");
    if (emptyState) emptyState.style.display = "none";
    const incompBanner = document.getElementById("pipeline-report-incomplete-banner");
    if (incompBanner) incompBanner.style.display = "none";
    if (elements.consoleProgram) elements.consoleProgram.style.display = "block";
    if (elements.btnPipelineSaveCorrected) {
      elements.btnPipelineSaveCorrected.disabled = false;
      elements.btnPipelineSaveCorrected.style.opacity = "1";
    }
    if (elements.outputTabsBar) elements.outputTabsBar.style.display = "flex";
    if (elements.outputContentArea) elements.outputContentArea.style.display = "block";
    if (artifacts) {
      handleExecutionResult(artifacts);
    }
  }

  const STAGE_TAB_MAPPING = {
    "lexical_analysis": "tab-out-lexer",
    "syntax_analysis": "tab-out-parser",
    "ast_construction": "tab-out-ast",
    "semantic_analysis": "tab-out-symbol",
    "symbol_table": "tab-out-symbol",
    "ir_generation": "tab-out-ir",
    "optimization": "tab-out-optimization",
    "sandbox_execution": "tab-out-program",
    "final_report": "tab-out-pipeline"
  };

  const STAGE_INFO_NUM = {
    source_input: 1,
    lexical_analysis: 2,
    syntax_analysis: 3,
    ast_construction: 4,
    semantic_analysis: 5,
    symbol_table: 6,
    ir_generation: 7,
    optimization: 8,
    code_generation: 9,
    code_validation: 10,
    security_analysis: 11,
    ai_security_analysis: 12,
    sandbox_execution: 13,
    final_report: 14
  };

  const STAGE_INFO_NAME = {
    source_input: "Source Input",
    lexical_analysis: "Lexical Analysis",
    syntax_analysis: "Syntax Analysis",
    ast_construction: "AST Construction",
    semantic_analysis: "Semantic Analysis",
    symbol_table: "Symbol Table",
    ir_generation: "IR Generation",
    optimization: "Optimization",
    code_generation: "Target Code Gen",
    code_validation: "Target Validation",
    security_analysis: "Security Analysis",
    ai_security_analysis: "AI Security Analysis",
    sandbox_execution: "Sandbox Execution",
    final_report: "Final Report"
  };

  const STAGE_NUM_TO_ID = {
    1: "source_input",
    2: "lexical_analysis",
    3: "syntax_analysis",
    4: "ast_construction",
    5: "semantic_analysis",
    6: "symbol_table",
    7: "ir_generation",
    8: "optimization",
    9: "code_generation",
    10: "code_validation",
    11: "security_analysis",
    12: "ai_security_analysis",
    13: "sandbox_execution",
    14: "final_report"
  };

  function updateTabModifiedIndicator() {
    if (!elements.tabDirtyIndicator || !state.currentFile) return false;
    const currentBuffer = state.editor ? state.editor.getValue() : "";
    const currentHash = sha256Sync(currentBuffer);
    const origHash = state.currentFile.originalHash || sha256Sync(state.currentFile.originalCode || "");
    const isModified = (currentHash !== origHash);

    if (isModified) {
      elements.tabDirtyIndicator.classList.add("visible");
    } else {
      elements.tabDirtyIndicator.classList.remove("visible");
    }

    if (state.currentFile.path && state.fileStore[state.currentFile.path]) {
      state.fileStore[state.currentFile.path].isDirty = isModified;
    }
    return isModified;
  }

  function isBufferVerifiedForSave() {
    const currentCode = state.editor ? state.editor.getValue() : "";
    if (!currentCode.trim()) return false;
    const currentHash = sha256Sync(currentCode);

    // 1. Must match currentBufferHash from completed pipeline run
    if (!state.pipeline.isFinished || !state.pipeline.lastCompletedRunId) return false;
    if (state.currentBufferHash !== currentHash) return false;

    // 2. Check stages 1-10 from the pipeline run:
    for (let s = 1; s <= 10; s++) {
      const sId = STAGE_NUM_TO_ID[s];
      const node = document.getElementById(`step-node-${sId}`);
      if (!node || (!node.classList.contains("status-passed") && !node.classList.contains("status-warning"))) {
        return false;
      }
    }

    // 3. Stage 11 (Security Analysis) must be passed or allowed warning
    const secNode = document.getElementById("step-node-security_analysis");
    if (!secNode || (!secNode.classList.contains("status-passed") && !secNode.classList.contains("status-warning"))) {
      return false;
    }

    // 4. Stage 12 (AI Security Analysis) must be passed or allowed warning (or skipped if toggle OFF)
    if (elements.toggleStage12Ai && elements.toggleStage12Ai.checked) {
      const aiNode = document.getElementById("step-node-ai_security_analysis");
      if (!aiNode || (!aiNode.classList.contains("status-passed") && !aiNode.classList.contains("status-warning"))) {
        return false;
      }
    }

    return true;
  }

  function updateSaveButtonState() {
    const btn = elements.btnPipelineSaveCorrected;
    if (!btn) return;
    const isVerified = isBufferVerifiedForSave();
    if (isVerified) {
      btn.style.opacity = "1";
      btn.setAttribute("title", "Save verified corrected code to My Saved Programs");
      btn.classList.remove("save-unverified");
    } else {
      btn.style.opacity = "0.5";
      btn.setAttribute("title", "Pipeline verification required (Stages 1–12) — click to confirm saving unverified code");
      btn.classList.add("save-unverified");
    }
  }

  function resetProgressiveTabs() {
    elements.outputTabBtns.forEach(btn => {
      const tabId = btn.getAttribute("data-tab");
      if (tabId === "tab-out-health" || tabId === "tab-out-program" || tabId === "tab-out-pipeline") {
        btn.style.display = "";
      } else {
        btn.style.display = "none";
      }
    });
  }

  function revealStageTab(stageId) {
    const targetTabId = STAGE_TAB_MAPPING[stageId];
    if (targetTabId) {
      const btn = document.querySelector(`.output-tab-btn[data-tab="${targetTabId}"]`);
      if (btn) btn.style.display = "";
    }
  }

  function hideStageTab(stageId) {
    const targetTabId = STAGE_TAB_MAPPING[stageId];
    if (targetTabId) {
      const btn = document.querySelector(`.output-tab-btn[data-tab="${targetTabId}"]`);
      if (btn) btn.style.display = "none";
    }
  }

  function showOutputBlockedState(blockingStageId, stageNum, stageName, reasonText, isSecurityBlocked = false) {
    state.pipeline.blockingStageId = blockingStageId;
    stageNum = stageNum || STAGE_INFO_NUM[blockingStageId] || 0;
    stageName = stageName || STAGE_INFO_NAME[blockingStageId] || blockingStageId;

    if (elements.outputWaitingState) elements.outputWaitingState.style.display = "none";
    if (elements.outputTabsBar) elements.outputTabsBar.style.display = "flex";
    if (elements.outputContentArea) elements.outputContentArea.style.display = "block";
    switchOutputTab("tab-out-program");

    const emptyState = document.getElementById("output-blocked-empty-state");
    const titleEl = document.getElementById("output-blocked-title");
    const reasonEl = document.getElementById("output-blocked-reason");
    const overrideBtn = document.getElementById("btn-blocked-override-run");

    if (emptyState) emptyState.style.display = "block";
    if (titleEl) titleEl.textContent = "No output generated.";
    if (reasonEl) {
      reasonEl.textContent = `Execution was blocked at Stage ${stageNum} (${stageName}): ${reasonText || "Prerequisite or policy gate unsatisfied."}`;
    }
    if (overrideBtn) {
      overrideBtn.style.display = isSecurityBlocked ? "inline-block" : "none";
    }
    if (elements.consoleProgram) {
      elements.consoleProgram.style.display = "none";
      elements.consoleProgram.textContent = "";
    }

    const incompBanner = document.getElementById("pipeline-report-incomplete-banner");
    if (incompBanner) {
      incompBanner.style.display = "block";
      incompBanner.textContent = `Incomplete report: pipeline stopped at Stage ${stageNum} (${reasonText || "Errors detected"}). Remaining stages were not executed.`;
    }
    if (elements.btnPipelineSaveCorrected) {
      elements.btnPipelineSaveCorrected.disabled = true;
      elements.btnPipelineSaveCorrected.style.opacity = "0.5";
    }
  }

  function initPipelineStepper() {
    if (!elements.pipelineStepper) return;
    elements.pipelineStepper.innerHTML = "";

    state.pipeline.stages.forEach((st, idx) => {
      const stepEl = document.createElement("div");
      const isUnavailable = !!st.unavailable;
      stepEl.className = isUnavailable ? "stepper-step status-skipped status-unavailable" : "stepper-step status-pending";
      stepEl.id = `step-node-${st.id}`;
      stepEl.setAttribute("data-stage-id", st.id);
      stepEl.title = `${st.name}: ${st.desc} (Click for stage details)`;

      const initialIcon = isUnavailable ? "⊘" : "○";
      stepEl.innerHTML = `
        <span class="stepper-step-icon">${initialIcon}</span>
        <span class="stepper-step-name">${st.name}</span>
        ${isUnavailable ? '<span class="stepper-badge-skipped">SKIPPED</span>' : ''}
        <span class="stepper-findings-badge" id="step-badge-${st.id}" style="display: none;">0</span>
      `;

      stepEl.addEventListener("click", () => {
        toggleStageDrawer(st.id);
      });

      elements.pipelineStepper.appendChild(stepEl);

      if (idx < state.pipeline.stages.length - 1) {
        const connector = document.createElement("div");
        connector.className = "stepper-connector";
        connector.textContent = "→";
        elements.pipelineStepper.appendChild(connector);
      }
    });

    if (elements.drawerCloseBtn) {
      elements.drawerCloseBtn.addEventListener("click", closeStageDrawer);
    }
  }

  function isSecurityResultValidForActiveBuffer(stageId) {
    if (!state.securityResults || !state.securityResults[stageId]) {
      return false;
    }
    const res = state.securityResults[stageId];
    const currentCode = state.editor ? state.editor.getValue() : "";
    const activeHash = sha256Sync(currentCode);
    if (!res.source_hash || res.source_hash !== activeHash) {
      return false;
    }
    const targetRunId = state.isExecuting ? state.pipeline.activeRunId : (state.pipeline.lastCompletedRunId || state.pipeline.activeRunId);
    if (!targetRunId || res.run_id !== targetRunId) {
      return false;
    }
    return true;
  }

  function resetPipelineStepper(isRunning = false) {
    if (!elements.pipelineStepper) return;
    if (elements.pipelineProgressFill) {
      elements.pipelineProgressFill.style.width = "0%";
      elements.pipelineProgressFill.className = isRunning ? "pipeline-progress-fill fill-running" : "pipeline-progress-fill";
    }
    if (elements.healthFixDelta) {
      elements.healthFixDelta.style.display = "none";
    }
    if (elements.pipelineStatusBadge) {
      if (isRunning) {
        elements.pipelineStatusBadge.textContent = "RUNNING";
        elements.pipelineStatusBadge.className = "pipeline-status-badge badge-running";
      } else {
        elements.pipelineStatusBadge.textContent = "Ready";
        elements.pipelineStatusBadge.className = "pipeline-status-badge badge-idle";
      }
    }
    if (elements.pipelineMetricStage) {
      elements.pipelineMetricStage.textContent = isRunning ? "Stage: Initializing..." : "Stage: Idle";
    }
    if (elements.pipelineMetricProgress) elements.pipelineMetricProgress.textContent = "0/14 Stages (0%)";
    if (elements.pipelineMetricTime) elements.pipelineMetricTime.textContent = "0.0 ms";

    state.pipeline.stages.forEach(st => {
      const node = document.getElementById(`step-node-${st.id}`);
      const isUnavailable = !!st.unavailable;
      if (node) {
        node.className = isUnavailable ? "stepper-step status-skipped status-unavailable" : "stepper-step status-pending";
        const icon = node.querySelector(".stepper-step-icon");
        if (icon) icon.textContent = isUnavailable ? "⊘" : "○";
        const badge = document.getElementById(`step-badge-${st.id}`);
        if (badge) {
          badge.textContent = "0";
          badge.className = "stepper-findings-badge";
          badge.style.display = "none";
        }
      }
      state.pipeline.stageData[st.id] = {
        status: isUnavailable ? "skipped" : "pending",
        duration_ms: 0,
        summary: "Pending initialization",
        details: {},
        findings_count: 0,
        skip_reason: ""
      };
    });

    state.pipeline.hasReceivedEventForRun = false;
    state.pipeline.isReportGenerated = false;
    state.pipeline.isReadyForReport = false;
    state.pipeline.isFinished = false;
    state.pipeline.pendingArtifacts = null;
    showOutputWaitingState(
      "Awaiting Compilation & Final Report",
      "Compiler artifacts will appear here after all required stages pass and the Final Report is generated."
    );
    closeStageDrawer();
  }

  function resetPipelineFullState(reason = "reset") {
    state.runCounter = (state.runCounter || 0) + 1;
    state.pipeline.activeRunId = null;
    state.pipeline.lastCompletedRunId = null;
    state.pipeline.blockingStageId = null;
    state.pipeline.pausedStage = null;
    state.pipeline.isPaused = false;
    state.pipeline.isFinished = false;
    state.pipeline.finishStatus = null;
    state.isExecuting = false;
    state.securityResults = {};
    state.security.findings = [];
    state.security.overallScore = 0;
    state.findingsStore = {};
    state.findingFixes = {};
    state.codeHealth = null;

    // Reset Code Health panel & gutter
    const scoreNumEl = document.getElementById("health-score-number");
    const gradeLetterEl = document.getElementById("health-grade-letter");
    const statusBadge = document.getElementById("health-status-text");
    const valInsecure = document.getElementById("health-val-insecure");
    const fillInsecure = document.getElementById("health-fill-insecure");
    const valDeadcode = document.getElementById("health-val-deadcode");
    const fillDeadcode = document.getElementById("health-fill-deadcode");
    const valDensity = document.getElementById("health-val-density");
    const fillDensity = document.getElementById("health-fill-density");
    if (scoreNumEl) scoreNumEl.textContent = "100";
    if (gradeLetterEl) gradeLetterEl.textContent = "GRADE A";
    if (statusBadge) { statusBadge.textContent = "HEALTHY"; statusBadge.className = "health-status-badge status-healthy"; }
    if (valInsecure) valInsecure.textContent = "0%";
    if (fillInsecure) fillInsecure.style.width = "0%";
    if (valDeadcode) valDeadcode.textContent = "0.0%";
    if (fillDeadcode) fillDeadcode.style.width = "0%";
    if (valDensity) valDensity.textContent = "0 / 100 lines";
    if (fillDensity) fillDensity.style.width = "0%";
    if (elements.btnHealthFixAll) {
      elements.btnHealthFixAll.style.display = "none";
      elements.btnHealthFixAll.textContent = "";
    }
    if (state.editor) {
      try { state.editor.clearGutter("health-gutter-markers"); } catch (e) { }
    }

    try {
      if (typeof sessionStorage !== "undefined") {
        sessionStorage.removeItem("vital_active_run_id");
      }
    } catch (e) { }

    // Clear consoles and compiler output
    if (elements.consoleProgram) elements.consoleProgram.textContent = "";
    if (elements.consolePipeline) elements.consolePipeline.textContent = "";
    if (elements.consoleLexer) elements.consoleLexer.textContent = "";
    if (elements.consoleParser) elements.consoleParser.textContent = "";
    if (elements.consoleAst) elements.consoleAst.textContent = "";
    if (elements.consoleIr) elements.consoleIr.textContent = "";
    if (elements.consoleSymbol) elements.consoleSymbol.textContent = "";
    if (elements.consoleOptimization) elements.consoleOptimization.textContent = "";

    // Clear timing badges
    if (elements.outputTimingBadge) elements.outputTimingBadge.textContent = "0 ms";
    if (elements.statusbarElapsed) elements.statusbarElapsed.textContent = "0 ms";

    const banner = document.getElementById("override-warning-banner");
    if (banner) banner.style.display = "none";
    const btnOverride = document.getElementById("btn-security-override-run");
    if (btnOverride) btnOverride.style.display = "none";
    const emptyState = document.getElementById("output-blocked-empty-state");
    if (emptyState) emptyState.style.display = "none";
    const incompBanner = document.getElementById("pipeline-report-incomplete-banner");
    if (incompBanner) incompBanner.style.display = "none";
    if (elements.pipelinePreflightStrip) elements.pipelinePreflightStrip.style.display = "none";
    if (elements.pipelinePreflightAccuracy) elements.pipelinePreflightAccuracy.style.display = "none";
    if (elements.healthAccuracyBadge) elements.healthAccuracyBadge.style.display = "none";
    state.activePreflightHealth = null;
    if (elements.btnRun) {
      elements.btnRun.setAttribute("title", "Execute Pipeline (Ctrl + Enter)");
      elements.btnRun.disabled = false;
    }
    if (elements.consoleProgram) {
      elements.consoleProgram.style.display = "block";
      elements.consoleProgram.textContent = "";
    }
    if (elements.btnPipelineSaveCorrected) {
      elements.btnPipelineSaveCorrected.disabled = true;
      elements.btnPipelineSaveCorrected.style.opacity = "0.5";
    }
    resetProgressiveTabs();
    showOutputWaitingState(
      "Awaiting Compilation",
      "Select a demo program or enter VITAL source code, then click ▶ Run to execute the 14-stage pipeline."
    );

    // Reset security scores
    if (elements.securityScoreVal) elements.securityScoreVal.textContent = "0";
    if (elements.securityScoreCircle) elements.securityScoreCircle.className = "security-score-circle";
    if (elements.securityFindingsList) {
      elements.securityFindingsList.innerHTML = '<div class="no-findings" style="text-align: center; color: var(--text-muted); padding: 40px 20px;">No security analysis run yet. Click ▶ Run to analyze.</div>';
    }
    if (elements.securityTabRiskPill) {
      elements.securityTabRiskPill.textContent = "0";
      elements.securityTabRiskPill.className = "risk-pill risk-clean";
      elements.securityTabRiskPill.style.display = "none";
    }
    if (elements.securityVerdict) elements.securityVerdict.textContent = "Not analyzed yet";

    // Reset pipeline stepper to idle
    resetPipelineStepper(false);

    // Notify backend to reset pipeline state
    if (typeof fetch === "function") {
      fetch("/api/pipeline/reset", { method: "POST" }).catch(() => { });
    }
  }

  const STAGE_ORDER = [
    "source_input",
    "lexical_analysis",
    "syntax_analysis",
    "ast_construction",
    "semantic_analysis",
    "symbol_table",
    "ir_generation",
    "optimization",
    "code_generation",
    "code_validation",
    "security_analysis",
    "ai_security_analysis",
    "sandbox_execution",
    "final_report"
  ];

  function invalidateDownstreamStages(fromStageId) {
    const fromIdx = STAGE_ORDER.indexOf(fromStageId);
    if (fromIdx === -1) return;

    for (let i = fromIdx + 1; i < STAGE_ORDER.length; i++) {
      const sid = STAGE_ORDER[i];
      state.pipeline.stageData[sid] = {
        status: "blocked",
        duration_ms: 0,
        summary: `Blocked: awaiting upstream stage completion (${fromStageId})`,
        details: {},
        findings_count: 0
      };

      const node = document.getElementById(`step-node-${sid}`);
      if (node) {
        node.className = "stepper-step status-blocked";
        const icon = node.querySelector(".stepper-step-icon");
        if (icon) icon.textContent = "⛔";
        const badge = document.getElementById(`step-badge-${sid}`);
        if (badge) badge.style.display = "none";
      }
    }

    state.pipeline.isReadyForReport = false;
    state.pipeline.isReportGenerated = false;
    state.pipeline.isFinished = false;
    state.pipeline.pendingArtifacts = null;
  }

  function invalidateAllStagesForNewRevision(newRevision) {
    state.pipeline.isReadyForReport = false;
    // Task D: Scope state.findingsStore by revision id
    if (state.findingsStore) {
      for (const [k, f] of Object.entries(state.findingsStore)) {
        if (f.revision_id && f.revision_id !== newRevision) {
          delete state.findingsStore[k];
        }
      }
    }
    state.pipeline.isReportGenerated = false;
    state.pipeline.isFinished = false;
    state.pipeline.pendingArtifacts = null;

    STAGE_ORDER.forEach(sid => {
      state.pipeline.stageData[sid] = {
        status: "stale",
        duration_ms: 0,
        summary: `Stale: source code updated to revision ${newRevision}`,
        details: {},
        findings_count: 0
      };

      const node = document.getElementById(`step-node-${sid}`);
      if (node) {
        node.className = "stepper-step status-stale";
        const icon = node.querySelector(".stepper-step-icon");
        if (icon) icon.textContent = "⏳";
        const badge = document.getElementById(`step-badge-${sid}`);
        if (badge) {
          badge.textContent = "STALE";
          badge.className = "stepper-findings-badge badge-stale";
          badge.style.display = "inline-block";
        }
      }
    });
  }

  function handlePipelineEvent(event) {
    if (!event) return;

    // Requirement 1: The frontend store ignores any message whose run_id isn't the active one
    if (event.run_id && state.pipeline.activeRunId && event.run_id !== state.pipeline.activeRunId) return;

    // Check if buffer has changed since run was started
    const currentCode = state.editor ? state.editor.getValue() : "";
    if (state.pipeline.compiledSource !== null && currentCode !== state.pipeline.compiledSource) return;
    if (state.currentBufferHash && sha256Sync(currentCode) !== state.currentBufferHash) return;
    if (event.revision_id && event.revision_id !== state.pipeline.revisionHash) return;
    if (event.run_id && state.pipeline.activeRunId && event.run_id !== state.pipeline.activeRunId) {
      console.warn(`[run] Ignoring event for mismatched run_id: ${event.run_id} !== active ${state.pipeline.activeRunId}`);
      return;
    }
    state.pipeline.hasReceivedEventForRun = true;

    // Requirement 4: Dev console log lines
    if (event.log_line) {
      console.log(event.log_line);
    }
    if (event.gate_log) {
      console.log(event.gate_log);
    }

    const { event: evtType, stage_id: rawStageId, progress_pct, completed_count, applicable_count, elapsed_ms, stage, summary, duration_ms, findings_count, skip_reason } = event;
    const stage_id = rawStageId ? (STAGE_ALIASES[rawStageId] || rawStageId) : null;

    // Update progress bar
    if (elements.pipelineProgressFill && typeof progress_pct === "number") {
      elements.pipelineProgressFill.style.width = `${progress_pct}%`;
    }
    if (elements.pipelineMetricProgress) {
      elements.pipelineMetricProgress.textContent = event.header_progress || `${completed_count || 0}/${applicable_count || 14} Stages (${progress_pct || 0}%)`;
    }
    if (elements.pipelineMetricTime && typeof elapsed_ms === "number") {
      elements.pipelineMetricTime.textContent = `${elapsed_ms} ms`;
    }
    if (elements.pipelineMetricStage && stage) {
      elements.pipelineMetricStage.textContent = `Stage: ${stage}`;
    }

    // Update Stage Node
    if (stage_id) {
      const node = document.getElementById(`step-node-${stage_id}`);
      const icon = node ? node.querySelector(".stepper-step-icon") : null;
      const badge = document.getElementById(`step-badge-${stage_id}`);

      // Sync findings into store if present in event details or stage completed/failed
      const stageFindingsFromEvent = (event.details && Array.isArray(event.details.findings)) ? event.details.findings : [];
      const computedStageStatus = event.stage_status || (evtType === "stage_start" ? "running" : evtType.replace("stage_", ""));
      if (evtType === "stage_complete" || evtType === "stage_failed" || evtType === "stage_warning") {
        syncFindingsIntoStore(stageFindingsFromEvent, [], null, stage_id, computedStageStatus);
        const fname = (state.currentFile && state.currentFile.filename) || (state.currentFile && state.currentFile.name) || "source.vital";
        const contentHash = (event.source_hash || event.revision_id || state.currentBufferHash || "unknown").slice(0, 8);
        const stageNumMatch = (stage || "").match(/^(\d+)/);
        const stageDisplay = stageNumMatch ? `Stage ${stageNumMatch[1]}` : (stage_id === "security_analysis" ? "Stage 11" : (stage_id === "ai_security_analysis" ? "Stage 12" : (stage_id || "Stage")));
        console.log(`[${stageDisplay}] scanning ${fname} @ ${contentHash} -> ${stageFindingsFromEvent.length || findings_count || 0} issues found`);
      }
      const actualFindingsCount = findings_count || stageFindingsFromEvent.length || 0;

      // Record run-scoped security results
      if (stage_id === "security_analysis" || stage_id === "ai_security_analysis") {
        if (evtType === "stage_complete" || evtType === "stage_failed" || evtType === "stage_warning") {
          state.securityResults[stage_id] = {
            run_id: event.run_id || state.pipeline.activeRunId,
            source_hash: event.source_hash || state.currentBufferHash || sha256Sync(currentCode),
            stage: stage_id,
            findings: stageFindingsFromEvent,
            created_at: Date.now()
          };
        }
      }

      // Cache stage data
      state.pipeline.stageData[stage_id] = {
        status: event.stage_status || (evtType === "stage_start" ? "running" : evtType.replace("stage_", "")),
        duration_ms: duration_ms || 0,
        summary: summary || "",
        details: event.details || {},
        findings_count: actualFindingsCount,
        skip_reason: skip_reason || ""
      };

      if (node) {
        const isActive = state.pipeline.activeDrawerStage === stage_id;
        const activeClass = isActive ? " active-drawer" : "";
        const isSecStage = stage_id === "security_analysis" || stage_id === "ai_security_analysis";
        const secValid = !isSecStage || isSecurityResultValidForActiveBuffer(stage_id);

        if (evtType === "stage_start") {
          node.className = `stepper-step status-running${activeClass}`;
          if (icon) icon.textContent = "⟳";
          node.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'nearest' });
        } else if (evtType === "stage_complete" || evtType === "stage_warning") {
          revealStageTab(stage_id);
          if (stage_id === "sandbox_execution") {
            const outTxt = (event.details && event.details.output !== undefined) ? event.details.output : "";
            if (elements.consoleProgram) {
              elements.consoleProgram.textContent = outTxt.trim() ? outTxt : "(Program produced no output)";
            }
          }
          if (stage_id === "final_report") {
            state.pipeline.isReportGenerated = true;
          }
          if (isSecStage && !secValid) {
            node.className = `stepper-step status-pending${activeClass}`;
            if (icon) icon.textContent = "○";
            if (badge) badge.style.display = "none";
          } else if (findings_count > 0) {
            node.className = `stepper-step status-warning${activeClass}`;
            if (icon) icon.textContent = "⚠";
            if (badge) {
              badge.textContent = `⚠ ${findings_count}`;
              badge.style.display = "inline-block";
            }
          } else {
            node.className = `stepper-step status-completed${activeClass}`;
            if (icon) icon.textContent = "✓";
            if (badge) badge.style.display = "none";
          }
        } else if (evtType === "stage_failed") {
          if (isSecStage && !secValid) {
            node.className = `stepper-step status-pending${activeClass}`;
            if (icon) icon.textContent = "○";
            if (badge) badge.style.display = "none";
          } else {
            node.className = `stepper-step status-failed${activeClass}`;
            if (icon) icon.textContent = "✕";
            node.title = event.error || event.summary || "Failed";
            if (badge) {
              badge.textContent = `✕ ${actualFindingsCount > 0 ? actualFindingsCount : 1}`;
              badge.className = "stepper-findings-badge badge-failed";
              badge.style.display = "inline-block";
            }
            if (elements.pipelineProgressFill) {
              elements.pipelineProgressFill.classList.add("fill-failed");
            }
          }
        } else if (evtType === "stage_blocked" || computedStageStatus === "blocked") {
          node.className = `stepper-step status-blocked${activeClass}`;
          if (icon) icon.textContent = "🔒";
          const blockReason = event.reason || event.summary || "Blocked by earlier stage";
          node.title = blockReason;
          if (badge) {
            badge.textContent = "BLOCKED";
            badge.className = "stepper-findings-badge badge-blocked";
            badge.style.display = "inline-block";
          }
        } else if (evtType === "stage_unavailable" || computedStageStatus === "unavailable") {
          node.className = `stepper-step status-unavailable${activeClass}`;
          if (icon) icon.textContent = "?";
          const unavailReason = event.reason || event.summary || "Stage unavailable";
          node.title = unavailReason;
          if (badge) {
            badge.textContent = "N/A";
            badge.className = "stepper-findings-badge badge-unavailable";
            badge.style.display = "inline-block";
          }
        } else if (evtType === "stage_stale" || computedStageStatus === "stale") {
          node.className = `stepper-step status-stale${activeClass}`;
          if (icon) icon.textContent = "⏳";
          if (badge) {
            badge.textContent = "STALE";
            badge.className = "stepper-findings-badge badge-stale";
            badge.style.display = "inline-block";
          }
        } else if (evtType === "stage_ready") {
          node.className = `stepper-step status-ready${activeClass}`;
          if (icon) icon.textContent = "★";
          if (badge) badge.style.display = "none";
        } else if (evtType === "stage_skipped" || computedStageStatus === "skipped") {
          node.className = `stepper-step status-skipped${activeClass}`;
          if (icon) icon.textContent = "⊘";
          if (badge) {
            badge.textContent = "SKIPPED";
            badge.className = "stepper-findings-badge badge-skipped";
            badge.style.display = "inline-block";
          }
        }
      }

      // If drawer is viewing this stage, refresh it
      if (state.pipeline.activeDrawerStage === stage_id) {
        renderStageDrawer(stage_id);
      }
    }

    // Pipeline Paused Event (Blocking Error in Progressive Execution)
    if (evtType === "pipeline_paused") {
      state.pipeline.isPaused = true;
      state.pipeline.isFinished = true;
      state.pipeline.finishStatus = "paused";
      state.pipeline.pausedStage = event.paused_stage;
      state.pipeline.blockingStageId = event.paused_stage;
      const bSid = event.paused_stage || "syntax_analysis";
      const bNum = event.paused_stage_num || (STAGE_INFO_NUM[bSid] || 0);
      const bName = event.paused_stage_name || (STAGE_INFO_NAME[bSid] || bSid);
      const bReason = event.reason || "Blocking error encountered";
      const isSecBlocked = (bSid === "security_analysis" || bSid === "ai_security_analysis");

      if (event.counts_by_stage) {
        state.pipeline.counts_by_stage = event.counts_by_stage;
      }
      if (event.issues) {
        state.pipeline.issues = event.issues;
      }
      if (Array.isArray(event.stages)) {
        event.stages.forEach(st => {
          if (st && st.id) {
            state.pipeline.stageData[st.id] = {
              status: st.status,
              duration_ms: st.duration_ms || 0,
              summary: st.summary || "",
              details: st.details || {},
              findings_count: st.findings_count || 0,
              skip_reason: st.skip_reason || ""
            };
          }
        });
      }

      if (elements.pipelineStatusBadge) {
        if (isSecBlocked || (event.header_message && event.header_message.includes("BLOCKED BY SECURITY"))) {
          elements.pipelineStatusBadge.textContent = "BLOCKED BY SECURITY";
          elements.pipelineStatusBadge.className = "pipeline-status-badge badge-blocked";
        } else {
          elements.pipelineStatusBadge.textContent = "FAILED";
          elements.pipelineStatusBadge.className = "pipeline-status-badge badge-failed";
        }
      }
      if (elements.pipelineProgressFill) {
        elements.pipelineProgressFill.classList.add("fill-failed");
      }
      if (elements.pipelineMetricStage) {
        elements.pipelineMetricStage.textContent = event.header_message || `Stopped at Stage ${bNum} (${bName})`;
      }
      showOutputBlockedState(bSid, bNum, bName, bReason, isSecBlocked);
      if (event.artifacts) {
        state.pipeline.pendingArtifacts = event.artifacts;
        handleExecutionResult(event.artifacts);
      }
      switchOutputTab("tab-out-program");
      if (event.paused_stage) {
        openStageDrawer(event.paused_stage);
      }

      // Evaluate prediction accuracy after pipeline pause
      try {
        const pauseStatus = isSecBlocked ? "blocked_by_security" : "failed";
        evaluatePredictionAccuracy(pauseStatus, {
          blocking_stage_num: bNum,
          blocking_stage_id: bSid,
          ...(event.artifacts || {})
        });
      } catch (predErr) {
        console.error("Error evaluating prediction accuracy on pause:", predErr);
      }

      try {
        state.isExecuting = false;
        runHealthAnalysis(true);
      } catch (hErr) {
        console.error("Error refreshing health on pause:", hErr);
      }

      try {
        updateAiFixRerunButtonVisibility(isSecBlocked ? "blocked_by_security" : "paused");
      } catch (fixErr) {
        console.error("Error updating AI fix rerun button on pause:", fixErr);
      }
    }

    // Pipeline Finish Event
    if (evtType === "pipeline_finish") {
      const status = event.status || event.overall_status || "completed";
      const normOverall = String(status).toLowerCase();
      const isComplete = (normOverall === "completed" || normOverall === "warning" || normOverall === "executed_with_override" || normOverall === "incomplete");

      state.pipeline.isFinished = true;
      state.pipeline.finishStatus = status;
      state.pipeline.lastCompletedRunId = event.run_id || state.pipeline.activeRunId;

      // 1. PRIMARY UI RENDERING FIRST
      const completedCount = event.completed_count !== undefined ? event.completed_count : (isComplete ? 14 : 0);
      const progressPct = event.progress_pct !== undefined ? event.progress_pct : (isComplete ? 100 : Math.round((completedCount / 14) * 100));
      const headerMsg = event.header_message || (status === "completed" ? "All 14 stages completed successfully" : (status === "warning" ? "Pipeline completed with warnings" : (status === "incomplete" ? "Pipeline incomplete: Stage 12 unavailable" : `Stopped: ${status.toUpperCase()}`)));

      if (elements.pipelineProgressFill) {
        elements.pipelineProgressFill.style.width = `${progressPct}%`;
        if (normOverall === "completed") {
          elements.pipelineProgressFill.className = "pipeline-progress-fill";
        } else if (normOverall === "warning" || normOverall === "incomplete") {
          elements.pipelineProgressFill.className = "pipeline-progress-fill fill-warning";
        } else {
          elements.pipelineProgressFill.className = "pipeline-progress-fill fill-failed";
        }
      }

      if (elements.pipelineMetricProgress) {
        elements.pipelineMetricProgress.textContent = event.header_progress || `${completedCount}/14 Stages (${progressPct}%)`;
      }

      if (elements.pipelineMetricStage) {
        elements.pipelineMetricStage.textContent = headerMsg;
      }

      if (elements.pipelineStatusBadge) {
        if (normOverall === "blocked_by_security") {
          elements.pipelineStatusBadge.textContent = "BLOCKED BY SECURITY";
          elements.pipelineStatusBadge.className = "pipeline-status-badge badge-blocked";
        } else if (normOverall === "executed_with_override") {
          elements.pipelineStatusBadge.textContent = "EXECUTED (OVERRIDE)";
          elements.pipelineStatusBadge.className = "pipeline-status-badge badge-warning";
        } else if (normOverall === "incomplete") {
          elements.pipelineStatusBadge.textContent = "INCOMPLETE";
          elements.pipelineStatusBadge.className = "pipeline-status-badge badge-incomplete";
        } else if (normOverall === "cancelled") {
          elements.pipelineStatusBadge.textContent = "CANCELLED";
          elements.pipelineStatusBadge.className = "pipeline-status-badge badge-incomplete";
        } else if (normOverall === "failed" || normOverall === "blocked") {
          elements.pipelineStatusBadge.textContent = "FAILED";
          elements.pipelineStatusBadge.className = "pipeline-status-badge badge-failed";
        } else if (normOverall === "warning") {
          elements.pipelineStatusBadge.textContent = "WARNING";
          elements.pipelineStatusBadge.className = "pipeline-status-badge badge-warning";
        } else if (normOverall === "completed") {
          elements.pipelineStatusBadge.textContent = "COMPLETED";
          elements.pipelineStatusBadge.className = "pipeline-status-badge badge-completed";
        } else {
          elements.pipelineStatusBadge.textContent = status.toUpperCase();
          elements.pipelineStatusBadge.className = `pipeline-status-badge badge-${normOverall}`;
        }
      }

      // Output and Report Rendering
      if (isComplete) {
        state.pipeline.isReportGenerated = true;
        if (event.artifacts) {
          showOutputArtifacts(event.artifacts);
          if (normOverall === "executed_with_override") {
            switchOutputTab("tab-out-program");
          } else {
            switchOutputTab("tab-out-pipeline");
          }
          if (event.artifacts.security) {
            try {
              renderSecurityFindings(
                event.artifacts.security.findings || [],
                event.artifacts.security.overall_risk_score,
                event.artifacts.security.overall_summary || "",
                Boolean(event.artifacts.security.syntax_blocked)
              );
            } catch (secErr) {
              console.error("Error rendering security findings:", secErr);
            }
          }
        }
      } else {
        const arts = event.artifacts || {};
        const bSid = arts.blocking_stage_id || state.pipeline.pausedStage || "execution";
        const bNum = arts.blocking_stage_num || (STAGE_INFO_NUM[bSid] || 0);
        const bName = arts.blocking_stage_name || (STAGE_INFO_NAME[bSid] || bSid);
        const bReason = arts.blocking_reason || event.header_message || "Execution blocked by stage gate policy.";
        const isSecBlocked = (normOverall === "blocked_by_security" || bSid === "security_analysis" || bSid === "ai_security_analysis");

        showOutputBlockedState(bSid, bNum, bName, bReason, isSecBlocked);
        if (event.artifacts) {
          handleExecutionResult(event.artifacts);
        }
        switchOutputTab("tab-out-program");
      }

      // 2. SECONDARY WORK GUARDED IN TRY/CATCH
      try {
        if (event.artifacts) {
          state.pipeline.pendingArtifacts = event.artifacts;
        }
        if (event.counts_by_stage) {
          state.pipeline.counts_by_stage = event.counts_by_stage;
        }
        if (event.issues) {
          state.pipeline.issues = event.issues;
        }

        if (Array.isArray(event.stages)) {
          event.stages.forEach(st => {
            if (st && st.id) {
              state.pipeline.stageData[st.id] = {
                status: st.status,
                duration_ms: st.duration_ms || 0,
                summary: st.summary || "",
                details: st.details || {},
                findings_count: st.findings_count || 0,
                skip_reason: st.skip_reason || ""
              };
              updatePipelineStageBadge(st.id, st.findings_count || 0, st.status);
            }
          });
          if (state.pipeline.activeDrawerStage) {
            renderStageDrawer(state.pipeline.activeDrawerStage);
          }
        }
      } catch (drawerErr) {
        console.error("Error rendering stage drawer / updating counts:", drawerErr);
      }

      // Evaluate prediction accuracy after run completes
      try {
        evaluatePredictionAccuracy(status, event.artifacts);
      } catch (predErr) {
        console.error("Error evaluating prediction accuracy:", predErr);
      }

      // Update Save Corrected Code button state after pipeline completes
      try {
        updateSaveButtonState();
      } catch (saveErr) {
        console.error("Error updating save button state:", saveErr);
      }

      try {
        updateAiFixRerunButtonVisibility(status);
      } catch (fixErr) {
        console.error("Error updating AI fix rerun button:", fixErr);
      }

      try {
        state.isExecuting = false;
        runHealthAnalysis(true);
      } catch (hErr) {
        console.error("Error refreshing health on finish:", hErr);
      }
    }
  }

  function updatePipelineStageBadge(stageId, count, status) {
    if ((stageId === "security_analysis" || stageId === "ai_security_analysis") && !isSecurityResultValidForActiveBuffer(stageId)) {
      count = 0;
      status = "pending";
    }
    const node = document.getElementById(`step-node-${stageId}`);
    const badge = document.getElementById(`step-badge-${stageId}`);
    if (node) {
      const isActive = state.pipeline.activeDrawerStage === stageId;
      const activeClass = isActive ? " active-drawer" : "";
      const icon = node.querySelector(".stepper-step-icon");
      if (status === "pending" || !status) {
        node.className = `stepper-step status-pending${activeClass}`;
        if (icon) icon.textContent = "○";
        if (badge) badge.style.display = "none";
        node.title = "";
        return;
      }
      if (status === "blocked") {
        node.className = `stepper-step status-blocked${activeClass}`;
        if (icon) icon.textContent = "🔒";
        node.title = "Blocked by earlier stage";
        if (badge) {
          badge.textContent = "BLOCKED";
          badge.className = "stepper-findings-badge badge-blocked";
          badge.style.display = "inline-block";
        }
        return;
      }
      if (status === "unavailable") {
        node.className = `stepper-step status-unavailable${activeClass}`;
        if (icon) icon.textContent = "?";
        node.title = "Stage unavailable";
        if (badge) {
          badge.textContent = "N/A";
          badge.className = "stepper-findings-badge badge-unavailable";
          badge.style.display = "inline-block";
        }
        return;
      }
      if (status === "failed") {
        node.className = `stepper-step status-failed${activeClass}`;
        if (icon) icon.textContent = "✕";
        if (badge) {
          badge.textContent = `✕ ${count > 0 ? count : 1}`;
          badge.className = "stepper-findings-badge badge-failed";
          badge.style.display = "inline-block";
        }
      } else if (count > 0 || status === "warning") {
        node.className = `stepper-step status-warning${activeClass}`;
        if (icon) icon.textContent = "⚠";
        if (badge) {
          badge.textContent = `⚠ ${count}`;
          badge.className = "stepper-findings-badge";
          badge.style.display = "inline-block";
        }
      } else if (status === "completed" || status === "passed") {
        node.className = `stepper-step status-completed${activeClass}`;
        if (icon) icon.textContent = "✓";
        if (badge) badge.style.display = "none";
        node.title = "";
      }
    }
  }

  function toggleStageDrawer(stageId) {
    if (state.pipeline.activeDrawerStage === stageId) {
      closeStageDrawer();
    } else {
      openStageDrawer(stageId);
    }
  }

  function openStageDrawer(stageId) {
    state.pipeline.activeDrawerStage = stageId;
    document.querySelectorAll(".stepper-step").forEach(s => s.classList.remove("active-drawer"));
    const node = document.getElementById(`step-node-${stageId}`);
    if (node) node.classList.add("active-drawer");

    renderStageDrawer(stageId);
    if (elements.stageOverlayBackdrop) {
      elements.stageOverlayBackdrop.style.display = "flex";
    }
    if (state.editor) {
      setTimeout(() => state.editor.refresh(), 50);
    }
  }

  function closeStageDrawer() {
    state.pipeline.activeDrawerStage = null;
    document.querySelectorAll(".stepper-step").forEach(s => s.classList.remove("active-drawer"));
    if (elements.stageOverlayBackdrop) {
      elements.stageOverlayBackdrop.style.display = "none";
    }
    if (state.editor) {
      setTimeout(() => state.editor.refresh(), 50);
    }
  }

  state.findingFixes = state.findingFixes || {};
  state.findingsStore = state.findingsStore || {};

  function syncFindingsIntoStore(scannedFindings, resolvedList = [], targetResolvedId = null, stageId = null, stageStatus = null) {
    state.findingsStore = state.findingsStore || {};

    const detectedIds = new Set();
    const detectedIdentifiers = new Set();
    const detectedRuleIds = new Set();

    // 1. Process scanned findings (which are currently detected by the compiler or scanner)
    (scannedFindings || []).forEach(f => {
      const fid = String(f.id || f.rule_id || "");
      if (!fid) return;
      detectedIds.add(fid);
      if (f.identifier) detectedIdentifiers.add(String(f.identifier));
      if (f.rule_id) detectedRuleIds.add(String(f.rule_id));

      const existing = state.findingsStore[fid];
      if (existing) {
        // Update line, column, evidence, excerpt
        existing.line = f.line;
        existing.column = f.column;
        existing.evidence = f.evidence || existing.evidence;
        existing.code_excerpt = f.code_excerpt || existing.code_excerpt;
        existing.identifier = f.identifier || existing.identifier;
        existing.explanation = f.explanation || existing.explanation;
        existing.potential_impact = f.potential_impact || existing.potential_impact;
        existing.severity = f.severity || existing.severity;

        // If finding was pending validation, but is still present in scannedFindings, validation failed!
        if (existing.status === "pending_validation") {
          existing.status = "open";
          existing.validation_status = "validation_failed";
        } else if (existing.status === "resolved") {
          // Re-opened because present in active source
          existing.status = "open";
          existing.validation_status = "still_detected";
        } else {
          existing.status = f.status || "open";
          existing.validation_status = f.validation_status || "still_detected";
        }
      } else {
        // New finding detected
        state.findingsStore[fid] = {
          ...f,
          id: fid,
          identifier: f.identifier || "",
          revision_id: state.sourceRevisionId || 1,
          status: f.status || "open",
          validation_status: f.validation_status || "still_detected"
        };
      }
    });

    // 2. Mark verified resolved findings from explicit list
    (resolvedList || []).forEach(rf => {
      const rfid = String(rf.id || rf.rule_id || "");
      Object.values(state.findingsStore).forEach(item => {
        const matchesTarget = (item.id === rfid) || (rf.identifier && item.identifier && String(item.identifier) === String(rf.identifier));
        if (matchesTarget && !detectedIds.has(item.id)) {
          item.status = "resolved";
          item.validation_status = "validated_resolved";
        }
      });
    });

    // 3. Stage-level revalidation reconciliation:
    // If a compiler or security stage has finished running, reconcile its findings:
    if (stageId) {
      const sLower = stageId.toLowerCase();
      Object.values(state.findingsStore).forEach(item => {
        const itemStageId = (item.stage_id || "").toLowerCase();
        const itemStageName = (item.stage || "").toLowerCase();
        let belongsToThisStage = false;
        if (sLower === "syntax_analysis") {
          belongsToThisStage = itemStageId.includes("syntax") || itemStageId.includes("parser") || itemStageName.includes("syntax") || itemStageName.includes("parser");
        } else if (sLower === "lexical_analysis") {
          belongsToThisStage = itemStageId.includes("lexical") || itemStageName.includes("lexical");
        } else if (sLower === "semantic_analysis") {
          belongsToThisStage = itemStageId.includes("semantic") || itemStageName.includes("semantic");
        } else if (sLower === "security_analysis") {
          belongsToThisStage = (itemStageId.includes("sec") || itemStageName.includes("sec")) && !itemStageId.includes("ai") && !itemStageName.includes("ai");
        } else {
          belongsToThisStage = (itemStageId === sLower || itemStageName === sLower);
        }

        if (belongsToThisStage) {
          let isDetected = detectedIds.has(item.id);
          if (!isDetected && item.identifier) {
            isDetected = detectedIdentifiers.has(String(item.identifier));
          }
          if (!isDetected) {
            // Finding is no longer detected by this stage's checks!
            if (stageStatus === "completed" || stageStatus === "warning" || item.status === "pending_validation") {
              item.status = "resolved";
              item.validation_status = "validated_resolved";
            }
          }
        }
      });
    }

    if (targetResolvedId && !detectedIds.has(targetResolvedId) && state.findingsStore[targetResolvedId]) {
      state.findingsStore[targetResolvedId].status = "resolved";
      state.findingsStore[targetResolvedId].validation_status = "validated_resolved";
    }
  }

  function getStageFindings(stageId) {
    if ((stageId === "security_analysis" || stageId === "ai_security_analysis") && !isSecurityResultValidForActiveBuffer(stageId)) {
      return [];
    }
    const data = (state.pipeline && state.pipeline.stageData && state.pipeline.stageData[stageId]) || {};
    if (data.details && Array.isArray(data.details.findings)) {
      syncFindingsIntoStore(data.details.findings, [], null, stageId, data.status);
      return data.details.findings.map(f => {
        const stored = state.findingsStore && state.findingsStore[f.id];
        if (stored && stored.status === "resolved") {
          return { ...f, status: "resolved" };
        }
        return f;
      });
    }

    if (Array.isArray(data.findings)) {
      syncFindingsIntoStore(data.findings, [], null, stageId, data.status);
      return data.findings.map(f => {
        const stored = state.findingsStore && state.findingsStore[f.id];
        if (stored && stored.status === "resolved") {
          return { ...f, status: "resolved" };
        }
        return f;
      });
    }

    if (Array.isArray(state.pipeline.issues)) {
      const matched = state.pipeline.issues.filter(i => (i.stage === stageId || i.stage_id === stageId));
      if (matched.length > 0) {
        return matched.map(f => {
          const stored = state.findingsStore && state.findingsStore[f.id];
          if (stored && stored.status === "resolved") {
            return { ...f, status: "resolved" };
          }
          return f;
        });
      }
    }

    const allStoreFindings = Object.values(state.findingsStore || {});
    return allStoreFindings.filter(f => {
      const s = (f.stage_id || "").toLowerCase();
      const st = (f.stage || "").toLowerCase();
      return s === stageId.toLowerCase() || st === stageId.toLowerCase();
    });
  }

  async function generateFinalReport(allowIncomplete = false) {
    const currentCode = state.editor ? state.editor.getValue() : "";
    const lang = state.currentFile ? state.currentFile.language : "English";

    // Check if source changed since compile
    if (state.pipeline.compiledSource && currentCode !== state.pipeline.compiledSource) {
      setStatus("Source code has been modified since the last compile pass. Please re-run the compiler before generating the final report.", "warning");
      return;
    }

    const stages = state.pipeline.stages || [];
    const stageData = state.pipeline.stageData || {};
    const unpassed = stages.filter(st => {
      if (st.id === "final_report") return false;
      const stStatus = stageData[st.id] ? stageData[st.id].status : "pending";
      return stStatus !== "completed" && stStatus !== "warning";
    });

    if (unpassed.length > 0) {
      allowIncomplete = true;
    }

    const btn = document.getElementById("btn-generate-final-report");
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = `<span class="ai-spin-icon">⟳</span> Assembling Final Report & Output Artifacts...`;
    }

    try {
      const resp = await sourceRequest("/api/pipeline/generate-report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code: currentCode,
          language: lang,
          run_id: state.pipeline.activeRunId,
          allow_incomplete: allowIncomplete
        })
      });
      const res = await resp.json();
      if (res.success) {
        state.pipeline.isReportGenerated = true;
        state.pipeline.pendingArtifacts = res.artifacts;
        state.pipeline.stageData["final_report"] = {
          status: res.is_incomplete ? "warning" : "completed",
          duration_ms: res.elapsed_ms || 1,
          summary: res.is_incomplete
            ? "Final Report generated with INCOMPLETE banner. Mandatory compilation stage(s) failed."
            : "Final Report generated successfully. All pipeline metrics assembled and output artifacts unlocked.",
          details: res
        };
        const node = document.getElementById("step-node-final_report");
        if (node) {
          node.className = res.is_incomplete ? "stepper-step status-warning active-drawer" : "stepper-step status-completed active-drawer";
          const icon = node.querySelector(".stepper-step-icon");
          if (icon) icon.textContent = res.is_incomplete ? "⚠" : "✓";
        }
        if (elements.pipelineStatusBadge) {
          elements.pipelineStatusBadge.textContent = res.is_incomplete ? "INCOMPLETE" : "COMPLETED";
          elements.pipelineStatusBadge.className = res.is_incomplete ? "pipeline-status-badge badge-warning" : "pipeline-status-badge badge-completed";
        }
        if (elements.pipelineProgressFill) {
          elements.pipelineProgressFill.style.width = "100%";
        }

        // Show artifacts and switch to pipeline report tab
        showOutputArtifacts(res.artifacts);
        switchOutputTab("tab-out-pipeline");
        setStatus(res.is_incomplete ? "Status: Final Report Generated (Incomplete)" : "Status: Compilation Completed | Final Report Generated", "ready");
        renderStageDrawer("final_report");
      } else {
        setStatus(`Report generation blocked: ${res.error || 'Prerequisites not satisfied.'}`, "error");
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = `📊 Generate Final Report & Unlock Output`;
        }
      }
    } catch (err) {
      console.error("Final report error:", err);
      setStatus(`Failed to generate final report: ${err.message}`, "error");
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = `📊 Generate Final Report & Unlock Output`;
      }
    }
  }

  function renderFinalReportStage(defn, data, status, duration, category) {
    const mandatoryStages = [
      "source_input", "lexical_analysis", "syntax_analysis", "ast_construction",
      "semantic_analysis", "symbol_table", "ir_generation", "optimization",
      "code_generation", "code_validation"
    ];
    const secondaryStages = [
      "security_analysis", "ai_security_analysis", "sandbox_execution"
    ];

    const currentCode = state.editor ? state.editor.getValue() : "";
    const currentRevision = state.sourceRevisionId || 1;
    const runRevision = state.pipeline.runRevision || 1;

    // Check if run exists for current revision and matches active code
    const runExistsForCurrentRevision = Boolean(
      state.pipeline.compiledSource &&
      currentCode === state.pipeline.compiledSource &&
      runRevision === currentRevision &&
      state.pipeline.isFinished
    );

    // Compute mandatory stages status (1-10)
    let mandatoryPassedCount = 0;
    let mandatoryWarnCount = 0;
    const mandatoryFailedStages = [];
    const uncompletedMandatoryStages = [];

    mandatoryStages.forEach(id => {
      const st = (state.pipeline.stageData[id] || {}).status || "pending";
      if (st === "completed" || st === "passed") {
        mandatoryPassedCount++;
      } else if (st === "warning") {
        mandatoryWarnCount++;
      } else if (st === "failed") {
        mandatoryFailedStages.push(id);
      } else {
        uncompletedMandatoryStages.push(id);
      }
    });

    const mandatory1To10PassedOrWarned = (mandatoryPassedCount + mandatoryWarnCount === 10) && (mandatoryFailedStages.length === 0);

    // Compute stages 11-13 status
    let secPassed = 0;
    let secWarn = 0;
    let secFailed = 0;
    let secSkipped = 0;

    secondaryStages.forEach(id => {
      const st = (state.pipeline.stageData[id] || {}).status || "pending";
      if (st === "completed" || st === "passed") secPassed++;
      else if (st === "warning") secWarn++;
      else if (st === "failed") secFailed++;
      else if (st === "skipped") secSkipped++;
    });

    // Determine whether report is generated or gate is shown:
    // "The drawer must read the CURRENT run state each time it opens: if stages 1-10 passed/warned and the run finished,
    // show the generated report directly, with no gate message. Show the gate only when no run exists for the current revision
    // or a mandatory stage failed."
    const isGenerated = Boolean(
      (runExistsForCurrentRevision && mandatory1To10PassedOrWarned && !state.pipeline.isPaused) ||
      (state.pipeline.isReportGenerated && !mandatoryFailedStages.length && runExistsForCurrentRevision)
    );
    const isReady = !isGenerated && state.pipeline.isReadyForReport;

    let gateCardHtml = "";
    if (isGenerated) {
      gateCardHtml = `
        <div class="drawer-card" style="border-left: 3px solid #10B981; background: #F0FDF4; padding: 14px 16px;">
          <div style="font-size: 14px; font-weight: 700; color: #065F46; display: flex; align-items: center; justify-content: space-between;">
            <div style="display: flex; align-items: center; gap: 8px;">
              <span>✓ Final Report Generated</span>
              <span class="stage-finding-badge badge-resolved">COMPLETED</span>
            </div>
          </div>
          <div style="font-size: 12px; color: #047857; margin-top: 6px; line-height: 1.5;">
            Compilation and mandatory IR optimization completed successfully. All compiler and pipeline artifacts are assembled and visible in the right-hand panel tabs.
          </div>
          <div style="margin-top: 14px; display: flex; gap: 10px; flex-wrap: wrap;">
            <button class="btn btn-primary" id="btn-final-save-corrected" style="flex: 1; padding: 8px 14px; font-weight: 700; font-size: 12.5px; background: #059669; border-color: #047857;">
              💾 Save Corrected Code
            </button>
            <button class="btn btn-secondary" id="btn-final-restore-original" style="flex: 1; padding: 8px 14px; font-weight: 600; font-size: 12.5px;">
              ↺ Restore Original
            </button>
          </div>
        </div>
      `;
    } else if (isReady) {
      gateCardHtml = `
        <div class="drawer-card" style="border-left: 3px solid #10B981; background: #F0FDF4; padding: 14px 16px;">
          <div style="font-size: 13.5px; font-weight: 700; color: #065F46; display: flex; align-items: center; gap: 8px;">
            <span>★ Ready to Generate Final Report</span>
          </div>
          <div style="font-size: 12px; color: #047857; margin-top: 6px; line-height: 1.5;">
            All 13 prerequisite compilation, optimization, and security stages have passed cleanly. Click below to complete compilation, assemble final metrics, and unlock the right-hand output artifacts.
          </div>
          <div style="margin-top: 12px;">
            <button class="btn btn-primary" id="btn-generate-final-report" style="width: 100%; padding: 10px 16px; font-weight: 700; font-size: 13px; background: #059669; border-color: #047857;">
              📊 Generate Final Report & Unlock Output
            </button>
          </div>
        </div>
      `;
    } else {
      let unpassedNames = "";
      if (!runExistsForCurrentRevision) {
        unpassedNames = "<li>Pipeline has not been executed yet for the current revision.</li>";
      } else if (mandatoryFailedStages.length > 0) {
        unpassedNames = mandatoryFailedStages.map(sId => {
          const sObj = state.pipeline.stages.find(s => s.id === sId) || { name: sId };
          return `<li><strong>${escapeHtml(sObj.name)}</strong> (Status: Failed)</li>`;
        }).join("");
      } else {
        const remainingUncompleted = uncompletedMandatoryStages.map(sId => {
          const sObj = state.pipeline.stages.find(s => s.id === sId) || { name: sId };
          return `<li><strong>${escapeHtml(sObj.name)}</strong> (Status: Pending)</li>`;
        }).join("");
        unpassedNames = remainingUncompleted || "<li>Pipeline has not been executed yet.</li>";
      }

      gateCardHtml = `
        <div class="drawer-card" style="border-left: 3px solid #EF4444; background: #FEF2F2; padding: 14px 16px;">
          <div style="font-size: 13.5px; font-weight: 700; color: #991B1B;">
            ⛔ Completion Gate Blocked
          </div>
          <div style="font-size: 12px; color: #7F1D1D; margin-top: 6px; line-height: 1.5;">
            The Final Report cannot be generated because required earlier stages (including mandatory Optimization) have not completed successfully:
            <ul style="margin: 8px 0 0 16px; padding: 0;">
              ${unpassedNames}
            </ul>
          </div>
          <div style="margin-top: 12px;">
            <button class="btn btn-warning" id="btn-generate-final-report" style="width: 100%; padding: 10px 16px; font-weight: 700; font-size: 13px; background: #D97706; border-color: #B45309; color: #FFF;">
              📊 Generate Final Report Anyway (Incomplete)
            </button>
          </div>
        </div>
      `;
    }

    const resCount = Object.values(state.findingsStore || {}).filter(f => f.status === "resolved").length;
    const remSec = state.security.findings.length;
    const lineCount = currentCode ? currentCode.split("\n").length : 0;
    const langName = state.currentFile ? state.currentFile.language : "Multilingual";

    // Dynamic Optimization status check to eliminate UI state inconsistency
    const optData = (state.pipeline && state.pipeline.stageData && state.pipeline.stageData["optimization"]) || {};
    const optStatus = (optData.status || "pending").toLowerCase();
    const optPassed = (optStatus === "completed" || optStatus === "passed");
    let optStatusLabel = "Pending Execution";
    let optStatusColor = "#D97706";
    if (optPassed) {
      const transformsCount = (optData.details && optData.details.transformations_count) || 0;
      optStatusLabel = transformsCount > 0 ? `Executed & Validated (${transformsCount} transforms)` : "Executed & Validated (0 transforms)";
      optStatusColor = "#059669";
    } else if (optStatus === "skipped") {
      optStatusLabel = "SKIPPED — Mandatory Gate Incomplete";
      optStatusColor = "#DC2626";
    } else if (optStatus === "failed") {
      optStatusLabel = "FAILED — Optimization Error";
      optStatusColor = "#DC2626";
    } else if (optStatus === "blocked") {
      optStatusLabel = "BLOCKED — Awaiting Valid IR";
      optStatusColor = "#DC2626";
    }

    // Format accurate stages label:
    // "Mandatory stages (1-10): 10/10 passed - Stages 11-13: 1 passed, 2 warnings"
    let mandatorySummary = "";
    if (mandatoryPassedCount === 10) {
      mandatorySummary = "10/10 passed";
    } else if (mandatoryPassedCount + mandatoryWarnCount === 10) {
      mandatorySummary = `${mandatoryPassedCount}/10 passed, ${mandatoryWarnCount} warning${mandatoryWarnCount === 1 ? '' : 's'}`;
    } else if (mandatoryFailedStages.length > 0) {
      mandatorySummary = `${mandatoryPassedCount + mandatoryWarnCount}/10 passed, ${mandatoryFailedStages.length} failed`;
    } else {
      mandatorySummary = `${mandatoryPassedCount + mandatoryWarnCount}/10 passed`;
    }

    const secParts = [];
    if (secPassed > 0) secParts.push(`${secPassed} passed`);
    if (secWarn > 0) secParts.push(`${secWarn} warning${secWarn === 1 ? '' : 's'}`);
    if (secFailed > 0) secParts.push(`${secFailed} failed`);
    if (secSkipped > 0) secParts.push(`${secSkipped} skipped`);
    const secondarySummary = secParts.length > 0 ? secParts.join(", ") : "pending";

    const stagesPassedAccuracyLabel = `Mandatory stages (1-10): ${mandatorySummary} - Stages 11-13: ${secondarySummary}`;

    const isWarningOverall = ((data && data.status === 'warning') || status === 'warning' || state.pipeline.finishStatus === 'warning');
    const pipelineStatusText = isGenerated
      ? (isWarningOverall ? 'COMPLETED WITH WARNINGS' : 'SUCCESSFUL / COMPLETE')
      : (isReady ? 'READY FOR REPORT' : 'PENDING PREREQUISITES');
    const pipelineStatusColor = isGenerated
      ? (isWarningOverall ? '#D97706' : '#059669')
      : (isReady ? '#2563EB' : '#DC2626');

    const summaryCardHtml = `
      <div class="drawer-card">
        <div class="drawer-card-header"><span class="drawer-card-title">Compilation & Pipeline Audit Summary</span></div>
        <div class="drawer-kv-row"><span class="drawer-kv-key">Source Language</span><span class="drawer-kv-val">${escapeHtml(langName)} (${lineCount} lines)</span></div>
        <div class="drawer-kv-row"><span class="drawer-kv-key">Target Language</span><span class="drawer-kv-val">Python 3 (Standard Library)</span></div>
        <div class="drawer-kv-row"><span class="drawer-kv-key">Pipeline Status</span><span class="drawer-kv-val" style="font-weight: 700; color: ${pipelineStatusColor};">${pipelineStatusText}</span></div>
        <div class="drawer-kv-row"><span class="drawer-kv-key">Compiler Stages</span><span class="drawer-kv-val">${stagesPassedAccuracyLabel}</span></div>
        <div class="drawer-kv-row"><span class="drawer-kv-key">Optimization Stage</span><span class="drawer-kv-val" style="color: ${optStatusColor}; font-weight: 700;">${optStatusLabel}</span></div>
        <div class="drawer-kv-row"><span class="drawer-kv-key">Resolved Diagnostics</span><span class="drawer-kv-val">${resCount} Issues Corrected</span></div>
        <div class="drawer-kv-row"><span class="drawer-kv-key">Remaining Warnings</span><span class="drawer-kv-val">${remSec} Flag(s)</span></div>
        <div class="drawer-kv-row"><span class="drawer-kv-key">Security Risk Score</span><span class="drawer-kv-val">${state.security.overallScore !== undefined ? `${state.security.overallScore}/100` : '0/100 (Clean)'}</span></div>
        <div class="drawer-kv-row"><span class="drawer-kv-key">Report Timestamp</span><span class="drawer-kv-val">${new Date().toLocaleTimeString()}</span></div>
      </div>
    `;

    let outputJumpButtons = "";
    if (isGenerated) {
      outputJumpButtons = `
        <div class="drawer-card">
          <div class="drawer-card-header"><span class="drawer-card-title">Unlocked Compiler Artifacts</span></div>
          <div style="font-size: 11.5px; color: #64748B; margin-bottom: 8px;">
            Jump directly to unlocked output panels:
          </div>
          <div style="display: flex; flex-direction: column; gap: 6px;">
            <button class="btn btn-secondary btn-sm" id="btn-jump-out-program" style="text-align: left; justify-content: flex-start;">
              ▶ View Sandboxed Execution Output →
            </button>
            <button class="btn btn-secondary btn-sm" id="btn-jump-out-ir" style="text-align: left; justify-content: flex-start;">
              🐍 View Generated Python Code (IR) →
            </button>
            <button class="btn btn-secondary btn-sm" id="btn-jump-out-pipeline" style="text-align: left; justify-content: flex-start;">
              📊 View Full Sequential Pipeline Report →
            </button>
          </div>
        </div>
      `;
    }

    elements.drawerStageBody.innerHTML = `
      <div class="drawer-card">
        <div class="drawer-card-header"><span class="drawer-card-title">Stage Purpose & Overview</span></div>
        <div class="drawer-desc-text">${escapeHtml(defn.desc)}</div>
        <div class="drawer-summary-box" style="${isGenerated ? 'border-left: 3px solid #10B981; background: #F0FDF4;' : (isReady ? 'border-left: 3px solid #2563EB; background: #EFF6FF;' : 'border-left: 3px solid #EF4444; background: #FEF2F2;')}">
          <strong>Execution Status:</strong> ${escapeHtml((data && data.summary) || (isGenerated ? "Final Report completed and published" : (isReady ? "Ready to generate report" : "Awaiting prerequisite stages")))}
        </div>
      </div>

      ${gateCardHtml}
      ${summaryCardHtml}
      ${outputJumpButtons}
    `;

    const genBtn = document.getElementById("btn-generate-final-report");
    if (genBtn) {
      genBtn.addEventListener("click", generateFinalReport);
    }

    const pBtn = document.getElementById("btn-jump-out-program");
    if (pBtn) pBtn.addEventListener("click", () => { closeStageDrawer(); switchOutputTab("tab-out-program"); });

    const irBtn = document.getElementById("btn-jump-out-ir");
    if (irBtn) irBtn.addEventListener("click", () => { closeStageDrawer(); switchOutputTab("tab-out-ir"); });

    const pipeBtn = document.getElementById("btn-jump-out-pipeline");
    if (pipeBtn) pipeBtn.addEventListener("click", () => { closeStageDrawer(); switchOutputTab("tab-out-pipeline"); });

    const saveFixedBtn = document.getElementById("btn-final-save-corrected");
    if (saveFixedBtn) {
      saveFixedBtn.addEventListener("click", saveCorrectedCode);
    }
    const restoreOrigBtn = document.getElementById("btn-final-restore-original");
    if (restoreOrigBtn) {
      restoreOrigBtn.addEventListener("click", restoreOriginalDemo);
    }
  }

  function renderStageDrawer(stageId) {
    if (!elements.drawerStageTitle || !elements.drawerStageBody) return;
    const defn = state.pipeline.stages.find(s => s.id === stageId) || { name: stageId, desc: "" };
    let data = state.pipeline.stageData[stageId] || { status: "pending", duration_ms: 0, summary: "Pending initialization" };

    if ((stageId === "security_analysis" || stageId === "ai_security_analysis") && !isSecurityResultValidForActiveBuffer(stageId)) {
      data = { status: "pending", duration_ms: 0, summary: "Not run yet. Run the compiler pipeline to evaluate this stage.", details: {}, findings_count: 0, skip_reason: "" };
    }

    const status = data.status || "pending";
    const duration = typeof data.duration_ms === "number" ? data.duration_ms : 0;
    const stageFindings = getStageFindings(stageId);
    const unresolvedFindings = stageFindings.filter(f => f.status !== "resolved");
    const resolvedFindings = stageFindings.filter(f => f.status === "resolved");
    let findingsCount = unresolvedFindings.length;
    const category = defn.category ? defn.category.toUpperCase() : "COMPILER";

    // Status pill rendering
    let pillClass = "pill-pending";
    let pillText = `○ Pending · In Queue`;
    let outcomeText = "Pending Execution";
    let outcomeClass = "";

    if (status === "completed" || status === "passed") {
      pillClass = "pill-completed";
      pillText = `✓ Passed · ${duration} ms`;
      if (findingsCount > 0) {
        outcomeText = `${findingsCount} Remaining Flag${findingsCount > 1 ? 's' : ''}`;
        outcomeClass = "text-amber";
      } else if (resolvedFindings.length > 0) {
        outcomeText = `All ${resolvedFindings.length} Resolved`;
        outcomeClass = "text-emerald";
      } else {
        outcomeText = "Verified Clean";
        outcomeClass = "text-emerald";
      }
    } else if (status === "running") {
      pillClass = "pill-running";
      pillText = `⟳ Running · Active`;
      outcomeText = "In Progress";
    } else if (status === "warning") {
      pillClass = "pill-warning";
      pillText = `⚠ Warning · ${duration} ms (${findingsCount} active issue${findingsCount > 1 ? 's' : ''})`;
      outcomeText = `${findingsCount} Active Issue${findingsCount > 1 ? 's' : ''}`;
      outcomeClass = "text-amber";
    } else if (status === "failed") {
      pillClass = "pill-failed";
      pillText = `✗ Failed · ${duration} ms (${findingsCount} error${findingsCount > 1 ? 's' : ''})`;
      outcomeText = `${findingsCount} Error${findingsCount > 1 ? 's' : ''}`;
      outcomeClass = "text-rose";
    } else if (status === "skipped") {
      pillClass = "pill-skipped";
      pillText = `⊘ Skipped · N/A`;
      outcomeText = "Bypassed (N/A)";
    } else if (status === "blocked") {
      pillClass = "pill-blocked";
      pillText = `⛔ Blocked · Downstream`;
      outcomeText = "Blocked by Prior Failure";
      outcomeClass = "text-rose";
    } else if (status === "ready") {
      pillClass = "pill-ready";
      pillText = `★ Ready · Completion Gate`;
      outcomeText = "Prerequisites Verified";
      outcomeClass = "text-emerald";
    }

    // Header Title Row
    elements.drawerStageTitle.innerHTML = `
      <div class="drawer-title-row">
        <span class="drawer-title-text">${escapeHtml(defn.name)}: ${escapeHtml(defn.desc.split(':')[0] || defn.desc)}</span>
        <span class="drawer-status-pill ${pillClass}">${pillText}</span>
        <span class="drawer-phase-badge">${category}</span>
      </div>
    `;

    if (stageId === "final_report") {
      renderFinalReportStage(defn, data, status, duration, category);
      return;
    }

    // Summary Box styling
    let summaryStyle = "";
    if (status === "completed") {
      summaryStyle = "border-left: 3px solid #10B981; background: #F0FDF4;";
    } else if (status === "warning") {
      summaryStyle = "border-left: 3px solid #F59E0B; background: #FFFBEB;";
    } else if (status === "failed") {
      summaryStyle = "border-left: 3px solid #EF4444; background: #FEF2F2;";
    } else if (status === "skipped") {
      summaryStyle = "border-left: 3px solid #94A3B8; background: #F8FAFC;";
    }

    // Educational notice for optimization stage
    let noticeHtml = "";
    if (stageId === "optimization") {
      noticeHtml = `
        <div class="drawer-card-notice" style="margin-top: 10px; padding: 10px 12px; border-radius: 4px; font-size: 11.5px; line-height: 1.5; color: #1E40AF; background: #EFF6FF; border-left: 3px solid #3B82F6;">
          <strong>⚡ Mandatory IR Optimization Pass:</strong>
          VITAL executes mandatory optimization passes over the generated Intermediate Representation (Constant Folding, Constant Propagation, Algebraic Simplification, Redundant Operation Elimination, and Dead Code Elimination) before emitting target code.
        </div>
      `;
    }

    // Overall Security Risk Score Card for Security Analysis
    let secRiskHtml = "";
    if (stageId === "security_analysis" || stageId === "ai_security_analysis") {
      const riskScore = (typeof state.security.overallScore === "number" || typeof state.security.overallScore === "string")
        ? state.security.overallScore
        : ((data.details && data.details.overall_risk_score !== undefined) ? data.details.overall_risk_score : 0);
      const isBlocked = riskScore === "BLOCKED";
      const scoreColor = isBlocked ? "#EF4444" : (riskScore >= 70 ? "#EF4444" : (riskScore >= 40 ? "#F59E0B" : "#10B981"));
      const unresSec = unresolvedFindings.length;
      const resSec = resolvedFindings.length;
      secRiskHtml = `
        <div class="drawer-card" style="display: flex; align-items: center; justify-content: space-between; padding: 12px 16px;">
          <div>
            <div style="font-size: 10.5px; font-weight: 700; text-transform: uppercase; color: #64748B; letter-spacing: 0.4px;">
              ${stageId === "ai_security_analysis" ? "Gemini AI Agent Status" : "Deterministic Security Risk Assessment"}
            </div>
            <div style="font-size: 12px; color: #334155; margin-top: 3px;">
              Unresolved Issues: <strong style="color: ${unresSec > 0 ? '#D97706' : '#059669'};">${unresSec}</strong> &bull; 
              Verified Resolved: <strong style="color: #059669;">${resSec}</strong> &bull; 
              Total Scanned: <strong>${stageFindings.length}</strong>
            </div>
          </div>
          <div style="text-align: right;">
            <div style="font-size: 20px; font-weight: 800; color: ${scoreColor}; font-family: var(--font-mono, monospace);">
              ${isBlocked ? "BLOCKED" : `${riskScore}/100`}
            </div>
            <div style="font-size: 10px; font-weight: 600; color: #64748B; text-transform: uppercase;">
              ${isBlocked ? "Syntax Blocked" : (unresSec > 0 ? (riskScore >= 70 ? "Critical Risk" : (riskScore >= 40 ? "Medium Risk" : "Active Security Issues")) : "Clean Verified")}
            </div>
          </div>
        </div>
      `;

      if (status === "failed" || (data.details && data.details.gate_decision === "BLOCK")) {
        secRiskHtml += `
          <div class="drawer-card" style="border-left: 3px solid #EF4444; background: #FEF2F2; padding: 12px 14px; margin-top: 10px;">
            <div style="font-weight: 700; color: #991B1B; font-size: 12.5px;">⚠️ Security Policy Gate: BLOCK</div>
            <div style="font-size: 11.5px; color: #7F1D1D; margin-top: 4px; line-height: 1.4;">
              CRITICAL/HIGH findings prevent automatic sandbox execution. For educational testing, you may override the gate and execute this code in an isolated sandbox.
            </div>
            <button class="btn btn-danger btn-sm btn-drawer-override-run" style="margin-top: 8px; background: #DC2626; color: #FFFFFF; font-weight: 600; cursor: pointer;">
              ⚠ Run anyway (unsafe, sandbox only)
            </button>
          </div>
        `;
      }

      if (stageId === "ai_security_analysis" && status === "unavailable") {
        secRiskHtml += `
          <div class="drawer-card" style="border-left: 3px solid #F59E0B; background: #FFFBEB; padding: 12px 14px; margin-top: 10px;">
            <div style="font-weight: 700; color: #92400E; font-size: 12.5px;">⚠️ Stage 12 Infrastructure Unavailable</div>
            <div style="font-size: 11.5px; color: #78350F; margin-top: 4px; line-height: 1.4;">
              ${escapeHtml(data.reason || data.summary || "AI Security Analysis could not run (API key missing, network timeout, or quota). Pipeline marked INCOMPLETE.")}
            </div>
            <div style="display: flex; gap: 8px; margin-top: 8px;">
              <button class="btn btn-secondary btn-sm" id="btn-retry-ai-security" style="font-weight: 600; cursor: pointer;">
                🔄 Retry AI Analysis
              </button>
              <button class="btn btn-primary btn-sm" id="btn-continue-without-ai" style="font-weight: 600; cursor: pointer; background: #4F46E5; border-color: #4338CA;">
                ⚡ Continue without AI analysis
              </button>
            </div>
          </div>
        `;
      }
    }

    // Clean Verification Card (when unresolved findings === 0 and clean, and no active security issues remain)
    let cleanVerificationHtml = "";
    if (findingsCount === 0 && (status === "completed" || status === "pending" || status === "running")) {
      cleanVerificationHtml = `
        <div class="drawer-card" style="border-left: 3px solid #10B981; background: #F0FDF4; padding: 10px 14px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 14px; color: #059669; font-weight: 700;">✓ Clean Stage Verification</span>
          </div>
          <div style="font-size: 11.5px; color: #047857; margin-top: 4px;">
            ${resolvedFindings.length > 0
          ? `All ${resolvedFindings.length} previously detected issue(s) have been verified as resolved.`
          : 'All checks for this compilation stage passed cleanly without diagnostics or detected vulnerabilities.'}
          </div>
        </div>
      `;
    }

    let stageFailureHtml = "";
    if (findingsCount === 0 && status === "failed") {
      stageFailureHtml = `
        <div class="drawer-card" style="border-left: 3px solid #EF4444; background: #FEF2F2; padding: 10px 14px;">
          <div style="font-size: 13px; color: #991B1B; font-weight: 700;">✗ Stage Execution Error</div>
          <div style="font-size: 11.5px; color: #7F1D1D; margin-top: 4px;">
            ${escapeHtml(data.reason || data.summary || "This stage encountered an execution failure without structured source diagnostics.")}
          </div>
        </div>
      `;
    } else if (findingsCount === 0 && status === "blocked" && stageId !== "sandbox_execution") {
      stageFailureHtml = `
        <div class="drawer-card" style="border-left: 3px solid #EF4444; background: #FEF2F2; padding: 10px 14px;">
          <div style="font-size: 13px; color: #991B1B; font-weight: 700;">⛔ Stage Blocked</div>
          <div style="font-size: 11.5px; color: #7F1D1D; margin-top: 4px;">
            ${escapeHtml(data.reason || data.summary || "This stage was blocked by an upstream gate failure; execution did not proceed.")}
          </div>
        </div>
      `;
    }

    // Diagnostic artifacts preview
    let artifactsHtml = "";
    const details = data.details || {};

    if (stageId === "lexical_analysis") {
      artifactsHtml = `
        <div class="drawer-card">
          <div class="drawer-card-header"><span class="drawer-card-title">Lexer Token Metrics</span></div>
          <div class="drawer-tokens-pills">
            <span class="drawer-token-pill">Status: <strong>Stream Generated</strong></span>
            <span class="drawer-token-pill">Tokens Log: <strong>tests/tokens.txt</strong></span>
            <span class="drawer-token-pill">Lexer Rule Engine: <strong>src/lexer.py</strong></span>
            <span class="drawer-token-pill">Multi-Script Support: <strong>UTF-8 Compatible</strong></span>
          </div>
        </div>
      `;
    } else if (stageId === "syntax_analysis") {
      artifactsHtml = `
        <div class="drawer-card">
          <div class="drawer-card-header"><span class="drawer-card-title">Grammar & Syntax Verification</span></div>
          <div class="drawer-kv-row"><span class="drawer-kv-key">Delimiter Check</span><span class="drawer-kv-val">${status === 'failed' ? 'Mismatched' : 'Balanced (Parentheses & Braces)'}</span></div>
          <div class="drawer-kv-row"><span class="drawer-kv-key">Grammar Specification</span><span class="drawer-kv-val">VITAL Formal Spec v2.0</span></div>
          <div class="drawer-kv-row"><span class="drawer-kv-key">Parser Validation Log</span><span class="drawer-kv-val">tests/parser_log.txt</span></div>
        </div>
      `;
    } else if (stageId === "ast_construction") {
      const nodeCount = details.node_count || "Parsed";
      artifactsHtml = `
        <div class="drawer-card">
          <div class="drawer-card-header"><span class="drawer-card-title">Abstract Syntax Tree (AST) Metrics</span></div>
          <div class="drawer-kv-row"><span class="drawer-kv-key">AST Node Count</span><span class="drawer-kv-val">${nodeCount}</span></div>
          <div class="drawer-kv-row"><span class="drawer-kv-key">Root Node</span><span class="drawer-kv-val">Module</span></div>
          <div class="drawer-kv-row"><span class="drawer-kv-key">AST Tree Log</span><span class="drawer-kv-val">tests/ast_log.txt</span></div>
        </div>
      `;
    } else if (stageId === "semantic_analysis" || stageId === "symbol_table") {
      const symbols = details.symbols || {};
      const symNames = Object.keys(symbols);
      artifactsHtml = `
        <div class="drawer-card">
          <div class="drawer-card-header"><span class="drawer-card-title">Symbol Table & Scope Resolution</span></div>
          <div class="drawer-kv-row"><span class="drawer-kv-key">Identifiers Resolved</span><span class="drawer-kv-val">${symNames.length} Identifier(s)</span></div>
          <div class="drawer-kv-row"><span class="drawer-kv-key">Scope Isolation</span><span class="drawer-kv-val">Global / Local Enclosing</span></div>
          <div class="drawer-kv-row"><span class="drawer-kv-key">Symbol File</span><span class="drawer-kv-val">tests/symbol_table.txt</span></div>
        </div>
      `;
    } else if (stageId === "optimization") {
      const optDetails = details || {};
      const passesApplied = optDetails.passes_applied || [];
      const transformsCount = optDetails.transformations_count !== undefined ? optDetails.transformations_count : 0;
      const valStatus = optDetails.validation_status || (status === "completed" ? "PASSED" : "PENDING");
      const proofMsg = optDetails.summary || "IR optimization analysis completed successfully.";
      const aiNote = optDetails.ai_analysis || "";

      artifactsHtml = `
        <div class="drawer-card">
          <div class="drawer-card-header"><span class="drawer-card-title">Intermediate Representation (IR) Optimization Proof</span></div>
          <div class="drawer-kv-row"><span class="drawer-kv-key">Optimization Status</span><span class="drawer-kv-val" style="font-weight:700; color:${status === 'completed' ? '#059669' : '#DC2626'};">${status === 'completed' ? 'PASSED & VALIDATED' : status.toUpperCase()}</span></div>
          <div class="drawer-kv-row"><span class="drawer-kv-key">Passes Applied</span><span class="drawer-kv-val">${passesApplied.length > 0 ? passesApplied.join(', ') : 'None (IR was already optimal)'}</span></div>
          <div class="drawer-kv-row"><span class="drawer-kv-key">Transformations</span><span class="drawer-kv-val">${transformsCount} transformation(s) applied</span></div>
          <div class="drawer-kv-row"><span class="drawer-kv-key">IR Validation</span><span class="drawer-kv-val" style="font-weight:600; color:${valStatus === 'PASSED' ? '#059669' : '#DC2626'};">${valStatus}</span></div>
          <div class="drawer-kv-row"><span class="drawer-kv-key">Passes Attempted</span><span class="drawer-kv-val">Constant Folding, Propagation, Dead Code, Redundant Op, Simplification</span></div>
          <div class="drawer-kv-row"><span class="drawer-kv-key">Optimizer Summary</span><span class="drawer-kv-val">${escapeHtml(proofMsg)}</span></div>
          ${aiNote ? `<div class="drawer-kv-row"><span class="drawer-kv-key">Gemini AI Review</span><span class="drawer-kv-val">${escapeHtml(aiNote)}</span></div>` : ''}
          ${(status !== 'completed' && status !== 'passed') ? `
            <div style="margin-top: 14px; padding-top: 10px; border-top: 1px solid #E2E8F0;">
              <button class="btn btn-primary" id="btn-retry-optimization-action" style="width: 100%; padding: 10px 14px; font-weight: 700; font-size: 12.5px; background: #2563EB; border-color: #1D4ED8;">
                ⚡ Run / Retry Optimization
              </button>
            </div>
          ` : ''}
        </div>
      `;
    } else if (stageId === "ir_generation" || stageId === "code_generation") {
      const lineCount = details.ir_lines || details.target_lines || "Generated";
      artifactsHtml = `
        <div class="drawer-card">
          <div class="drawer-card-header"><span class="drawer-card-title">Code Generation Metrics</span></div>
          <div class="drawer-kv-row"><span class="drawer-kv-key">Emitted Code Lines</span><span class="drawer-kv-val">${lineCount} Lines</span></div>
          <div class="drawer-kv-row"><span class="drawer-kv-key">Target Runtime</span><span class="drawer-kv-val">Python 3 (Standard Library)</span></div>
          <div class="drawer-kv-row"><span class="drawer-kv-key">Artifact Path</span><span class="drawer-kv-val">tests/ir.txt</span></div>
        </div>
      `;
    } else if (stageId === "security_analysis" || stageId === "ai_security_analysis") {
      artifactsHtml = `
        <div class="drawer-card">
          <div class="drawer-card-header"><span class="drawer-card-title">Security Checks Performed</span></div>
          <div class="drawer-tokens-pills">
            <span class="drawer-token-pill">Homoglyphs: <strong>Checked</strong></span>
            <span class="drawer-token-pill">Command Injection: <strong>Checked</strong></span>
            <span class="drawer-token-pill">Path Traversal: <strong>Checked</strong></span>
            <span class="drawer-token-pill">Null Byte Injection: <strong>Checked</strong></span>
            <span class="drawer-token-pill">IDOR & Ownership: <strong>Checked</strong></span>
            <span class="drawer-token-pill">Gemini Model: <strong>${escapeHtml(((state.security && (state.security.aiStatus?.model || state.security.ollamaStatus?.model)) || "gemini-flash-lite-latest"))}</strong></span>
          </div>
        </div>
      `;
    } else if (stageId === "sandbox_execution") {
      const exitCode = details.exit_code !== undefined ? details.exit_code : 0;
      const timedOut = details.timed_out || false;
      const killedBy = details.killed_by || "none";
      const excType = details.exception_type || "None";
      const excMsg = details.exception_message || "";
      const tbStr = details.traceback_str || "";

      if (status === "blocked") {
        artifactsHtml = `
          <div class="drawer-card" style="border-left: 3px solid #EF4444; background: #FEF2F2; padding: 12px 14px;">
            <div style="font-weight: 700; color: #991B1B; font-size: 12.5px;">⛔ Sandbox Execution Blocked</div>
            <div style="font-size: 11.5px; color: #7F1D1D; margin-top: 4px; line-height: 1.4;">
              Stage 13 was blocked by ${escapeHtml(data.reason || data.summary || "earlier security gate; nothing ran.")}
            </div>
          </div>
        `;
      } else {
        artifactsHtml = `
          <div class="drawer-card">
            <div class="drawer-card-header"><span class="drawer-card-title">Sandbox Execution Results</span></div>
            <div class="drawer-kv-row"><span class="drawer-kv-key">Status</span><span class="drawer-kv-val" style="font-weight:700; color:${status === 'completed' || status === 'passed' ? '#059669' : '#DC2626'};">${status === 'completed' || status === 'passed' ? 'COMPLETED (CLEAN)' : 'EXECUTION FAILED'}</span></div>
            <div class="drawer-kv-row"><span class="drawer-kv-key">Exit Code</span><span class="drawer-kv-val"><code>${exitCode}</code></span></div>
            <div class="drawer-kv-row"><span class="drawer-kv-key">Killed By</span><span class="drawer-kv-val"><code>${escapeHtml(killedBy)}</code></span></div>
            <div class="drawer-kv-row"><span class="drawer-kv-key">Timed Out</span><span class="drawer-kv-val">${timedOut ? '<strong style="color:#DC2626;">Yes (5s timeout)</strong>' : 'No'}</span></div>
            ${excType && excType !== 'None' ? `<div class="drawer-kv-row"><span class="drawer-kv-key">Exception</span><span class="drawer-kv-val" style="color:#DC2626; font-weight:600;">${escapeHtml(excType)}${excMsg ? `: ${escapeHtml(excMsg)}` : ''}</span></div>` : ''}
            ${details.policy_violations && details.policy_violations.length > 0 ? `<div class="drawer-kv-row"><span class="drawer-kv-key">Blocked Ops</span><span class="drawer-kv-val" style="color:#D97706; font-weight:700;">${details.policy_violations.length} dangerous operation(s) stubbed</span></div>` : ''}
            <div class="drawer-kv-row"><span class="drawer-kv-key">Execution Output</span><span class="drawer-kv-val">tests/output.txt</span></div>
            ${tbStr ? `
              <details style="margin-top: 10px;">
                <summary style="cursor: pointer; font-size: 11.5px; font-weight: 600; color: #475569;">View Full Sandbox Traceback ▾</summary>
                <pre style="margin-top: 6px; padding: 10px; background: #0F172A; color: #F8FAFC; border-radius: 4px; font-size: 11px; line-height: 1.4; overflow-x: auto; max-height: 250px;"><code>${escapeHtml(tbStr)}</code></pre>
              </details>
            ` : ''}
          </div>
        `;
      }
    }

    // Scrollable Findings Section (when findings exist)
    let findingsSectionHtml = "";
    if (stageFindings.length > 0) {
      let cardsHtml = "";
      stageFindings.forEach(f => {
        const fid = String(f.id || "");
        const sev = (f.severity || "Medium");
        const sevClass = sev.toLowerCase();
        const locStr = f.line ? `Line ${f.line}${f.column ? `:${f.column}` : ''}` : "";
        const locHtml = f.line ? `
          <button class="finding-loc-btn" data-line="${f.line}" data-col="${f.column || 1}" title="Navigate to line in editor">
            📍 ${state.currentFile ? escapeHtml(state.currentFile.filename) : 'Code'}: ${locStr}
          </button>
        ` : '';

        const codeSnippet = f.code_excerpt || f.evidence || "";
        const excerptHtml = codeSnippet ? `
          <pre class="stage-finding-excerpt"><code>${escapeHtml(codeSnippet)}</code></pre>
        ` : '';

        // If this finding is resolved, render as resolved card
        if (f.status === "resolved") {
          cardsHtml += `
            <div class="stage-finding-card status-resolved" id="card-finding-${escapeHtml(fid)}">
              <div class="stage-finding-header">
                <div class="stage-finding-title-group">
                  <span class="stage-finding-badge badge-resolved">✓ RESOLVED</span>
                  <span class="stage-finding-title" style="text-decoration: line-through; color: #475569;">${escapeHtml(f.title || fid)}</span>
                </div>
                <div style="display: flex; align-items: center; gap: 6px;">
                  <span class="stage-finding-rule">${escapeHtml(f.rule_id || fid)}</span>
                  <span class="drawer-phase-badge">${escapeHtml(f.stage || defn.name)}</span>
                </div>
              </div>

              ${locHtml}
              ${excerptHtml}

              <div class="resolved-tag-box" style="margin-top: 4px;">
                <span>✓ Validated Resolution: This issue has been neutralized in the current working buffer.</span>
              </div>

              <div class="stage-finding-actions" style="margin-top: 6px;">
                <span style="font-size: 11px; color: #047857;">
                  Validation Status: <strong>Validated Resolved</strong> &bull; Severity: ${escapeHtml(sev)}
                </span>
                <span style="font-size: 11px; color: #64748B;">
                  Rule: <code>${escapeHtml(f.rule_id || fid)}</code>
                </span>
              </div>
            </div>
          `;
          return;
        }

        const impactHtml = f.potential_impact ? `
          <div class="stage-finding-impact">
            <strong>Potential Impact:</strong> ${escapeHtml(f.potential_impact)}
          </div>
        ` : '';

        const remText = f.remediation || f.suggested_code || "";
        const remHtml = remText ? `
          <div class="stage-finding-remediation">
            <strong>Recommended Correction:</strong> ${escapeHtml(remText)}
          </div>
        ` : '';

        let badgeHtml = `<span class="stage-finding-badge badge-${sevClass}">${escapeHtml(sev)}</span>`;
        let cardStatusClass = `sev-${sevClass}`;
        let statusLabel = escapeHtml(f.status || 'Active');
        if (f.status === "needs_manual_fix" || f.status === "unresolved" || f.is_manual || f.manual_reason) {
          badgeHtml = '<span class="stage-finding-badge" style="background:#FEF3C7; color:#92400E; border:1px solid #FCD34D;">⚠ UNRESOLVED</span>';
          statusLabel = "Unresolved";
        } else if (f.status === "pending_validation") {
          badgeHtml = '<span class="stage-finding-badge" style="background:#DBEAFE; color:#1E40AF; border:1px solid #93C5FD;">⟳ PENDING VALIDATION</span>';
          statusLabel = "Pending Validation (Fix Applied)";
        } else if (f.validation_status === "validation_failed") {
          badgeHtml = '<span class="stage-finding-badge" style="background:#FEE2E2; color:#991B1B; border:1px solid #FCA5A5;">✗ VALIDATION FAILED</span>';
          statusLabel = "Validation Failed (Still Detected)";
        } else if (f.status === "fix_proposed") {
          badgeHtml = '<span class="stage-finding-badge" style="background:#EDE9FE; color:#5B21B6; border:1px solid #C4B5FD;">✨ FIX PROPOSED</span>';
          statusLabel = "Fix Proposed (Review Diff)";
        }

        let manualBoxHtml = "";
        if (f.status === "needs_manual_fix" || f.status === "unresolved" || f.is_manual || f.manual_reason) {
          const mReason = f.manual_reason || f.reason || "Automated patch pending verification or requires additional context.";
          manualBoxHtml = `
            <div class="stage-finding-manual-box" style="margin-top: 8px; background: rgba(245, 158, 11, 0.1); border: 1px solid #f59e0b; border-radius: 4px; padding: 8px;">
              <div style="color: #d97706; font-size: 12px; font-weight: 600;">⚠ Resolution status:</div>
              <div style="color: #475569; font-size: 12px; margin-top: 2px;">${escapeHtml(mReason)}</div>
              ${remText ? `
                <div style="margin-top: 6px; display: flex; justify-content: space-between; align-items: center;">
                  <span style="font-size: 11px; font-weight: 600; color: #475569;">Recommended Code:</span>
                  <button class="btn btn-secondary btn-sm btn-copy-manual-snippet" data-snippet="${escapeHtml(remText)}" style="font-size: 11px; padding: 2px 6px;">📋 Copy Code</button>
                </div>
              ` : ''}
            </div>
          `;
        }

        cardsHtml += `
          <div class="stage-finding-card ${cardStatusClass}" id="card-finding-${escapeHtml(fid)}">
            <div class="stage-finding-header">
              <div class="stage-finding-title-group">
                ${badgeHtml}
                <span class="stage-finding-title">${escapeHtml(f.title || fid)}</span>
              </div>
              <div style="display: flex; align-items: center; gap: 6px;">
                <span class="stage-finding-rule">${escapeHtml(f.rule_id || fid)}</span>
                <span class="drawer-phase-badge">${escapeHtml(f.stage || defn.name)}</span>
              </div>
            </div>

            ${locHtml}
            ${excerptHtml}

            <div class="stage-finding-explanation">
              <strong>Problem:</strong> ${escapeHtml(f.explanation || f.title || 'Diagnostic reported by stage analysis.')}
            </div>

            ${impactHtml}
            ${remHtml}
            ${manualBoxHtml}

            <div class="stage-finding-actions">
              <span style="font-size: 11px; color: #64748B;">
                Status: <strong>${statusLabel}</strong> &bull; Confidence: ${escapeHtml(f.confidence || 'confirmed')}
              </span>
              <div class="finding-action-btns">
                ${isFixEnabledForCurrentFile() ? `
                <button class="btn btn-primary btn-sm btn-drawer-suggest-fix" data-finding-id="${escapeHtml(fid)}" data-stage-id="${escapeHtml(stageId)}">
                  <span>✨ Suggest Fix</span>
                </button>
                ` : ''}
              </div>
            </div>

            <div class="inline-remediation-container" id="inline-remediation-${escapeHtml(fid)}"></div>
          </div>
        `;
      });

      const countLabel = resolvedFindings.length > 0
        ? `${unresolvedFindings.length} Active &bull; ${resolvedFindings.length} Resolved`
        : `${stageFindings.length} Issue${stageFindings.length > 1 ? 's' : ''} Detected`;

      let fixAllBannerHtml = "";
      if (unresolvedFindings.length > 0 && isFixEnabledForCurrentFile()) {
        fixAllBannerHtml = `
          <div class="stage-fix-all-banner" id="stage-fix-all-banner-${stageId}">
            <div class="fix-all-content">
              <div class="fix-all-text-group">
                <div class="fix-all-title-row">
                  <span class="fix-all-badge">${escapeHtml(defn.name)} Remediation</span>
                  <span class="fix-all-title">Stage Automated Correction</span>
                </div>
                <p class="fix-all-desc">
                  Resolve all <strong>${unresolvedFindings.length}</strong> active diagnostic ${unresolvedFindings.length === 1 ? 'issue' : 'issues'} in this stage using deterministic & AI validated patches.
                </p>
              </div>
              <div class="fix-all-btn-group">
                <button class="btn btn-primary btn-fix-all" id="btn-fix-all-${stageId}" data-stage-id="${stageId}">
                  <span class="btn-fix-all-icon">⚡</span>
                  <span class="btn-fix-all-text">Fix with AI (${unresolvedFindings.length})</span>
                </button>
              </div>
            </div>
            <div class="fix-all-progress-bar" id="fix-all-progress-${stageId}" style="display: none;">
              <span class="spinner" style="display:inline-block; width:14px; height:14px; border:2px solid #93C5FD; border-top-color:#1D4ED8; border-radius:50%; animation:spin 1s linear infinite;"></span>
              <span id="fix-all-status-text-${stageId}">Analyzing all ${unresolvedFindings.length} diagnostics and synthesizing correction...</span>
            </div>
          </div>
        `;
      }

      findingsSectionHtml = `
        <div class="stage-findings-section">
          ${fixAllBannerHtml}
          <div class="stage-findings-header">
            <span class="stage-findings-title">
              <span>🔍 Stage Findings & Diagnostics</span>
              <span class="stage-findings-count-badge">${countLabel}</span>
            </span>
            <span style="font-size: 11px; color: #64748B;">Inspect and remediate each issue individually or click Fix All above</span>
          </div>
          <div class="stage-findings-scroll-container">
            ${cardsHtml}
          </div>
        </div>
      `;
    }

    // Direct Tab Link Action (to right-hand output artifacts)
    let linkTab = "";
    let buttonLabel = "View Associated Stage Tab →";
    if (stageId === "source_input") { linkTab = "tab-out-pipeline"; buttonLabel = "View Pipeline Report →"; }
    else if (stageId === "lexical_analysis") { linkTab = "tab-out-lexer"; buttonLabel = "View Lexer Token Stream →"; }
    else if (stageId === "syntax_analysis") { linkTab = "tab-out-parser"; buttonLabel = "View Parser Validation Log →"; }
    else if (stageId === "ast_construction") { linkTab = "tab-out-ast"; buttonLabel = "View Visual AST Hierarchy →"; }
    else if (stageId === "semantic_analysis" || stageId === "symbol_table") { linkTab = "tab-out-symbol"; buttonLabel = "View Symbol Table & Semantics →"; }
    else if (stageId === "ir_generation" || stageId === "optimization" || stageId === "code_generation") { linkTab = "tab-out-ir"; buttonLabel = "View Intermediate Representation (IR) →"; }
    else if (stageId === "code_validation") { linkTab = "tab-out-pipeline"; buttonLabel = "View Validation Report →"; }
    else if (stageId === "security_analysis" || stageId === "ai_security_analysis") { linkTab = "tab-out-pipeline"; buttonLabel = "View Pipeline Report →"; }
    else if (stageId === "sandbox_execution") { linkTab = "tab-out-program"; buttonLabel = "View Sandboxed Execution Output →"; }
    else if (stageId === "final_report") { linkTab = "tab-out-pipeline"; buttonLabel = "View Full Pipeline Report →"; }

    let actionBtnHtml = "";
    if (linkTab) {
      actionBtnHtml = `
        <div class="drawer-footer-actions" style="margin-top: 8px;">
          <button class="btn btn-secondary btn-sm" id="btn-jump-tab-${stageId}">
            ${escapeHtml(buttonLabel)}
          </button>
        </div>
      `;
    }

    elements.drawerStageBody.innerHTML = `
      <!-- Card 1: Overview -->
      <div class="drawer-card">
        <div class="drawer-card-header"><span class="drawer-card-title">Stage Purpose & Overview</span></div>
        <div class="drawer-desc-text">${escapeHtml(defn.desc)}</div>
        <div class="drawer-summary-box" style="${summaryStyle}">
          <strong>Execution Status:</strong> ${escapeHtml(data.summary || data.status)}
        </div>
        ${noticeHtml}
      </div>

      <!-- Card 2: 4-Tile Stat Grid -->
      <div class="drawer-card">
        <div class="drawer-card-header"><span class="drawer-card-title">Performance & Diagnostic Metrics</span></div>
        <div class="drawer-stats-grid">
          <div class="drawer-stat-card">
            <div class="drawer-stat-label">Execution Duration</div>
            <div class="drawer-stat-value">${status === 'skipped' ? 'N/A' : `${duration} ms`}</div>
          </div>
          <div class="drawer-stat-card">
            <div class="drawer-stat-label">Findings / Warnings</div>
            <div class="drawer-stat-value ${findingsCount > 0 ? 'text-amber' : 'text-emerald'}">${findingsCount}</div>
          </div>
          <div class="drawer-stat-card">
            <div class="drawer-stat-label">Compiler Phase</div>
            <div class="drawer-stat-value">${category}</div>
          </div>
          <div class="drawer-stat-card">
            <div class="drawer-stat-label">Verification Outcome</div>
            <div class="drawer-stat-value ${outcomeClass}">${outcomeText}</div>
          </div>
        </div>
      </div>

      <!-- Card: Security Overall Score (if Security stage) -->
      ${secRiskHtml}

      <!-- Card: Clean Verification Banner (if no findings) -->
      ${cleanVerificationHtml}

      <!-- Card: Stage Failure / Blocked Banner (if no findings) -->
      ${stageFailureHtml}

      <!-- Findings Section (Scrollable with Per-Issue Cards & Fix All Banner) -->
      ${findingsSectionHtml}

      <!-- Specific Artifacts -->
      ${artifactsHtml}

      <!-- Tab Jump Action -->
      ${actionBtnHtml}
    `;

    // Bind Fix All Button
    const fixAllBtn = document.getElementById(`btn-fix-all-${stageId}`);
    if (fixAllBtn) {
      fixAllBtn.addEventListener("click", () => {
        handleFixAllClick(stageId);
      });
    }

    // Bind Jump Button
    const jumpBtn = document.getElementById(`btn-jump-tab-${stageId}`);
    if (jumpBtn) {
      jumpBtn.addEventListener("click", () => {
        switchOutputTab(linkTab);
        const outPanel = document.getElementById("panel-output");
        if (outPanel) {
          outPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
        }
      });
    }

    // Bind Optimization Retry Button
    const optRetryBtn = document.getElementById("btn-retry-optimization-action");
    if (optRetryBtn) {
      optRetryBtn.addEventListener("click", async () => {
        optRetryBtn.disabled = true;
        optRetryBtn.innerHTML = `<span class="ai-spin-icon">⟳</span> Running IR Optimizer Passes...`;
        try {
          const resp = await sourceRequest("/api/pipeline/retry-optimization", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              code: state.editor.getValue(),
              language: state.currentFile.language,
              use_ai: false
            })
          });
          const res = await resp.json();
          if (res.success) {
            state.pipeline.stageData["optimization"] = {
              status: "completed",
              duration_ms: (res.details && res.details.elapsed_ms) || 1,
              summary: res.summary || "IR optimization completed successfully.",
              details: res.details || {}
            };
            const optNode = document.getElementById("step-node-optimization");
            if (optNode) {
              optNode.className = "stepper-step status-completed";
              const icon = optNode.querySelector(".stepper-step-icon");
              if (icon) icon.textContent = "✓";
            }
            renderStageDrawer("optimization");
            setStatus("Status: IR Optimization succeeded. Automatically continuing pipeline to Code Generation...", "running");
            await runCompiler("code_generation", true);
          } else {
            setStatus(`Optimization failed: ${res.error || 'Optimization error'}`, "error");
            optRetryBtn.disabled = false;
            optRetryBtn.innerHTML = `⚡ Run / Retry Optimization`;
          }
        } catch (err) {
          setStatus(`Optimization error: ${err.message}`, "error");
          optRetryBtn.disabled = false;
          optRetryBtn.innerHTML = `⚡ Run / Retry Optimization`;
        }
      });
    }

    // Bind Location Jump Buttons
    elements.drawerStageBody.querySelectorAll(".finding-loc-btn").forEach(locBtn => {
      locBtn.addEventListener("click", () => {
        const line = parseInt(locBtn.getAttribute("data-line"), 10);
        const col = parseInt(locBtn.getAttribute("data-col"), 10) || 1;
        if (state.editor && line > 0) {
          state.editor.setCursor(line - 1, Math.max(0, col - 1));
          state.editor.focus();
          const lineHandle = state.editor.addLineClass(line - 1, "background", "cm-line-highlight");
          setTimeout(() => {
            state.editor.removeLineClass(lineHandle, "background", "cm-line-highlight");
          }, 2000);
        }
      });
    });

    // Bind Per-Finding Suggest Fix Buttons
    elements.drawerStageBody.querySelectorAll(".btn-drawer-suggest-fix").forEach(btn => {
      btn.addEventListener("click", () => {
        const fid = btn.getAttribute("data-finding-id");
        const sid = btn.getAttribute("data-stage-id") || stageId;
        handleSuggestFixClick(fid, sid);
      });
    });

    // Bind Copy Manual Snippet Buttons
    elements.drawerStageBody.querySelectorAll(".btn-copy-manual-snippet").forEach(btn => {
      btn.addEventListener("click", () => {
        const snippet = btn.getAttribute("data-snippet") || "";
        if (snippet && navigator.clipboard) {
          navigator.clipboard.writeText(snippet);
          const orig = btn.textContent;
          btn.textContent = "✓ Copied!";
          setTimeout(() => { btn.textContent = orig; }, 2000);
        }
      });
    });

    // Bind Drawer Security Override Button
    const drawerOverrideBtn = elements.drawerStageBody.querySelector(".btn-drawer-override-run");
    if (drawerOverrideBtn) {
      drawerOverrideBtn.addEventListener("click", () => {
        if (confirm("WARNING: This code contains security vulnerabilities detected by SAST/AI.\n\nExecuting this code will run it in an isolated sandbox with a 5-second timeout, but execution could be dangerous or produce unexpected behavior.\n\nDo you want to proceed with SECURITY OVERRIDE?")) {
          closeStageDrawer();
          runCompiler(null, false, true);
        }
      });
    }

    // Bind Retry AI Security Button
    const retryAiBtn = document.getElementById("btn-retry-ai-security");
    if (retryAiBtn) {
      retryAiBtn.addEventListener("click", async () => {
        retryAiBtn.disabled = true;
        retryAiBtn.innerHTML = `⟳ Retrying Stage 12...`;
        try {
          const resp = await sourceRequest("/api/pipeline/retry-stage", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              stage_id: "ai_security_analysis",
              code: state.editor.getValue(),
              language: state.currentFile.language
            })
          });
          const res = await resp.json();
          if (res.success && res.stage_result) {
            handlePipelineEvent({
              run_id: state.pipeline.activeRunId,
              stage_id: "ai_security_analysis",
              stage: "AI Security Analysis",
              stage_status: res.stage_result.status,
              summary: res.stage_result.summary,
              details: res.stage_result.details,
              findings_count: (res.stage_result.details && res.stage_result.details.findings) ? res.stage_result.details.findings.length : 0
            });
            renderStageDrawer("ai_security_analysis");
          } else {
            setStatus(`Retry failed: ${res.error || (res.stage_result && res.stage_result.reason) || 'Stage unavailable'}`, "error");
            renderStageDrawer("ai_security_analysis");
          }
        } catch (err) {
          setStatus(`Retry error: ${err.message}`, "error");
          renderStageDrawer("ai_security_analysis");
        }
      });
    }

    const continueWithoutAiBtn = document.getElementById("btn-continue-without-ai");
    if (continueWithoutAiBtn) {
      continueWithoutAiBtn.addEventListener("click", () => {
        const toggle = document.getElementById("toggle-stage12-ai");
        if (toggle) toggle.checked = false;
        closeStageDrawer();
        runCompiler();
      });
    }

    // Re-hydrate any already proposed fixes for findings in this stage
    stageFindings.forEach(f => {
      const fid = String(f.id || "");
      if (state.findingFixes && state.findingFixes[fid] && state.findingFixes[fid].proposed_source) {
        renderInlineRemediation(fid, stageId, state.findingFixes[fid]);
      }
    });
  }

  async function persistWorkingSourceToBackend(label = "User edit") {
    if (!state.currentFile || !state.currentFile.path) {
      return { success: false, error: "No active file loaded" };
    }
    const relPath = state.currentFile.path;
    const currentCode = state.editor ? state.editor.getValue() : "";

    try {
      const resp = await sourceRequest("/api/working-source/save", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          path: relPath,
          source_code: currentCode,
          label: label
        })
      });
      const data = await resp.json();
      if (data.success) {
        state.sourceRevisionId = data.source_revision;
        state.contentHash = data.content_hash;
        if (state.pipeline) {
          state.pipeline.sourceRevisionId = data.source_revision;
        }
        if (state.fileStore[relPath]) {
          state.fileStore[relPath].workingBuffer = currentCode;
          state.fileStore[relPath].source_revision = data.source_revision;
          state.fileStore[relPath].content_hash = data.content_hash;
          state.fileStore[relPath].isDirty = Boolean(data.is_modified);
        }
        persistWorkingBuffersToStorage();
        if (data.is_modified) {
          elements.tabDirtyIndicator.classList.add("visible");
        } else {
          elements.tabDirtyIndicator.classList.remove("visible");
        }
        updateUndoButtonsState(Boolean(data.can_undo));
        return { success: true, data };
      } else {
        return { success: false, error: data.error || "Save rejected by server" };
      }
    } catch (err) {
      console.error("Backend working source persist error:", err);
      return { success: false, error: String(err) };
    }
  }

  let fixAllWatchdogTimer = null;
  let fixAllButtonCurrentState = "ready";

  function setFixAllButtonState(newState, fixableCount = 0, errorMsg = null) {
    fixAllButtonCurrentState = newState;
    const btn = elements.btnHealthFixAll;
    if (!btn) return;

    if (fixAllWatchdogTimer) {
      clearTimeout(fixAllWatchdogTimer);
      fixAllWatchdogTimer = null;
    }

    if (newState === "loading") {
      btn.style.display = "inline-flex";
      btn.disabled = true;
      btn.className = "btn-health-fix-all loading";
      btn.innerHTML = '<span class="spinner-sm"></span> Analysing...';

      // 10-second watchdog
      fixAllWatchdogTimer = setTimeout(() => {
        if (fixAllButtonCurrentState === "loading") {
          console.warn("[health] Fix All analysis watchdog timed out after 10s");
          setFixAllButtonState("error", 0, "Watchdog timeout");
        }
      }, 10000);

    } else if (newState === "ready") {
      btn.disabled = false;
      btn.className = "btn-health-fix-all ready";
      if (fixableCount > 0) {
        btn.style.display = "inline-flex";
        btn.textContent = `⚡ Fix All Issues (${fixableCount})`;
      } else {
        btn.style.display = "none";
        btn.textContent = "";
      }
    } else if (newState === "error") {
      btn.style.display = "inline-flex";
      btn.disabled = false;
      btn.className = "btn-health-fix-all error";
      btn.textContent = "Analysis failed - Retry";
    } else if (newState === "none") {
      btn.style.display = "none";
      btn.disabled = false;
      btn.className = "btn-health-fix-all";
      btn.textContent = "";
    }
  }

  function openFixAllInitialModal(issues, totalCount, fixableCount) {
    if (!elements.fixModalOverlay) return;
    if (typeof closeStageDrawer === "function") {
      closeStageDrawer();
    }

    elements.fixModalTitle.textContent = `Fix All: all (0/${totalCount} Issues Resolved)`;
    elements.fixModalSeverity.style.display = "inline-flex";
    elements.fixModalSeverity.textContent = `${totalCount} Issue${totalCount > 1 ? 's' : ''}`;
    elements.fixModalSeverity.className = "fix-modal-badge sev-medium";

    if (elements.fixModalSource) {
      elements.fixModalSource.textContent = "Deterministic & AI";
      elements.fixModalSource.className = "fix-modal-source-badge badge-gemini-ai";
    }
    if (elements.fixModalValidation) {
      elements.fixModalValidation.textContent = "Pending fix generation";
      elements.fixModalValidation.className = "fix-modal-val-badge val-not-tested";
    }
    if (elements.fixAiRefiningBar) {
      elements.fixAiRefiningBar.style.display = "none";
    }
    if (elements.fixModalCard) {
      elements.fixModalCard.classList.add("fix-all-mode");
    }

    // Hide legacy single diff preview elements
    if (elements.fixModalExplanation) elements.fixModalExplanation.style.display = "none";
    const resultsPanel = document.getElementById("fix-modal-results-panel");
    if (resultsPanel) resultsPanel.style.display = "none";
    const viewModes = document.querySelector(".diff-view-modes");
    if (viewModes) viewModes.style.display = "none";
    const diffContainerUnified = document.getElementById("diff-container-unified");
    if (diffContainerUnified) diffContainerUnified.style.display = "none";
    const diffContainerSplit = document.getElementById("diff-container-split");
    if (diffContainerSplit) diffContainerSplit.style.display = "none";
    if (elements.fixModalSuspectWarning) elements.fixModalSuspectWarning.style.display = "none";

    // Render each issue as an interactive card
    if (elements.fixModalPerErrorContainer) {
      elements.fixModalPerErrorContainer.style.display = "flex";
      let html = `
        <div class="fix-all-summary-bar">
          <div class="fix-all-summary-title">
            <span class="fix-summary-dot has-unfixed"></span>
            <span>${totalCount} issue${totalCount > 1 ? 's' : ''} identified — ready to fix</span>
          </div>
          <button type="button" class="btn-toggle-all-sections" id="btn-toggle-all-diffs">Collapse all</button>
        </div>
        <div class="fix-error-cards-list" style="display: flex; flex-direction: column; gap: 10px;">
      `;

      issues.forEach((iss, idx) => {
        const isDet = (iss.fixer_hint || "").startsWith("deterministic");
        const fixerLabel = isDet ? "[deterministic fix]" : "[AI fix]";
        const fixerBadgeClass = isDet ? "badge-det" : "badge-ai";
        const sev = (iss.severity || "medium").toLowerCase();
        const stageName = (iss.stage || "").replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase());

        html += `
          <div class="fix-error-card expanded" data-error-index="${idx + 1}" data-issue-id="${escapeHtml(iss.id || '')}">
            <div class="fix-error-card-header" role="button" tabindex="0">
              <div class="fix-error-header-main">
                <span class="fix-error-chevron">▼</span>
                <div class="fix-error-title-wrap">
                  <span class="fix-error-number">#${idx + 1}:</span>
                  <span class="fix-error-title" title="${escapeHtml(iss.message || iss.kind)}">${escapeHtml(iss.kind || 'Issue')}: ${escapeHtml(iss.message || '')}</span>
                  <span class="fix-error-line-badge">Ln ${iss.line || 1}:${iss.column || 1}</span>
                </div>
              </div>
              <div class="fix-error-header-badges">
                <span class="health-code-badge">${escapeHtml(stageName)}</span>
                <span class="fix-modal-badge sev-${sev}">${escapeHtml(iss.severity || 'medium')}</span>
                <span class="fix-badge-source ${fixerBadgeClass}">${fixerLabel}</span>
              </div>
            </div>
            <div class="fix-error-card-body">
              ${iss.evidence ? `<pre style="margin: 4px 0; background: var(--bg-primary, #0D1117); color: #c9d1d9; padding: 6px 10px; border-radius: 4px; font-family: monospace; font-size: 11px; overflow-x: auto;"><code>${escapeHtml(iss.evidence)}</code></pre>` : ''}
              <div style="font-size: 11px; color: var(--text-muted, #8b949e); margin-top: 4px;">
                <strong>Stage:</strong> ${escapeHtml(stageName)} | <strong>Planned Fixer:</strong> ${isDet ? 'Deterministic Rule Engine' : 'Gemini AI Assistant'}
              </div>
            </div>
          </div>
        `;
      });

      html += `</div>`;
      elements.fixModalPerErrorContainer.innerHTML = html;
      bindErrorSectionToggles(elements.fixModalPerErrorContainer);
    }

    if (elements.btnApplyFix) {
      elements.btnApplyFix.disabled = false;
      elements.btnApplyFix.textContent = `Apply ${fixableCount} fixes`;
    }
    if (elements.btnRejectFix) {
      elements.btnRejectFix.textContent = "Cancel";
    }

    state.security.pendingFix = {
      is_fix_all: true,
      is_initial_view: true,
      stage_id: "all",
      total_diagnostics: totalCount,
      fixable_count: fixableCount,
      issues: issues,
      source_revision: state.sourceRevisionId || 1,
      file_path: state.currentFile ? state.currentFile.path : "",
      current_source: state.editor ? state.editor.getValue() : "",
      proposed_source: null
    };

    updateUndoButtonsState();
    elements.fixModalOverlay.style.display = "flex";
  }

  async function handleStageTargetedFixAll() {
    if (fixAllButtonCurrentState === "error") {
      runHealthAnalysis(true);
      return;
    }

    const currentCode = state.editor ? state.editor.getValue() : "";
    if (!currentCode.trim()) {
      setStatus("No source code in editor to fix.", "warning");
      return;
    }

    const currentHash = sha256Sync(currentCode);
    let cached = state.issuesCache && state.issuesCache[currentHash];

    // If still in loading state, wait briefly for in-flight analysis to finish
    if (fixAllButtonCurrentState === "loading" && !cached) {
      for (let i = 0; i < 20; i++) {
        await new Promise(r => setTimeout(r, 100));
        cached = state.issuesCache && state.issuesCache[currentHash];
        if (cached) break;
      }
    }

    // If not cached or missing issues, fetch synchronously from /api/issues/collect
    if (!cached || !cached.issues) {
      setFixAllButtonState("loading");
      try {
        const resp = await fetch("/api/issues/collect", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            source: currentCode,
            language: state.currentFile ? state.currentFile.language : "English"
          })
        });
        if (resp.ok) {
          cached = await resp.json();
          if (!state.issuesCache) state.issuesCache = {};
          state.issuesCache[currentHash] = cached;
          setFixAllButtonState("ready", cached.fixable_count || cached.total_count);
        } else {
          setFixAllButtonState("error");
          return;
        }
      } catch (err) {
        setFixAllButtonState("error");
        return;
      }
    }

    const issues = cached.issues || [];
    const totalCount = cached.total_count !== undefined ? cached.total_count : issues.length;
    const fixableCount = cached.fixable_count !== undefined ? cached.fixable_count : totalCount;

    if (totalCount === 0) {
      return;
    }

    // Immediately open Fix Modal (< 200ms) with the issues listed!
    openFixAllInitialModal(issues, totalCount, fixableCount);
  }

  async function handleFixAllClick(stageId) {
    const btn = document.getElementById(`btn-fix-all-${stageId}`);
    const progress = document.getElementById(`fix-all-progress-${stageId}`);
    const statusText = document.getElementById(`fix-all-status-text-${stageId}`);

    const stageFindings = getStageFindings(stageId);
    const unresolved = stageFindings.filter(f => f.status !== "resolved");
    if (unresolved.length === 0) {
      if (statusText) {
        statusText.textContent = "All diagnostics in this stage have been resolved.";
        if (progress) progress.style.display = "flex";
        setTimeout(() => { if (progress) progress.style.display = "none"; }, 2500);
      }
      setStatus("No unresolved diagnostics to fix in this stage.", "info");
      return;
    }

    if (btn) btn.disabled = true;
    if (progress) progress.style.display = "flex";
    const firstDiagLine = unresolved[0] && (unresolved[0].line || unresolved[0].target_line) ? ` L${unresolved[0].line || unresolved[0].target_line}` : "";
    if (statusText) statusText.textContent = `Fixing 1/${unresolved.length}: ${stageId}${firstDiagLine}...`;

    const currentCode = state.editor ? state.editor.getValue() : "";
    const lang = state.currentFile ? state.currentFile.language : "English";
    const filePath = state.currentFile ? state.currentFile.path : "";

    try {
      setStatus(`Fixing 1/${unresolved.length}: ${stageId}${firstDiagLine}...`, "running");
      const resp = await sourceRequest("/api/ai/fix-all", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          stage_id: stageId,
          source_code: currentCode,
          language: lang,
          file_path: filePath,
          diagnostics: unresolved,
          stage_only: true
        })
      });

      const data = await resp.json();
      if (!data.success && (!data.fixes || data.fixes.length === 0) && (!data.manual_fixes || data.manual_fixes.length === 0)) {
        if (progress) progress.style.display = "none";
        if (btn) btn.disabled = false;
        setStatus("Fix All was unable to resolve stage issues", "warning");
      }

      if (progress) progress.style.display = "none";
      if (btn) btn.disabled = false;

      // Open Fix Modal in Fix-All mode
      openFixAllModal(stageId, data, unresolved);
    } catch (err) {
      console.error("Fix All error:", err);
      if (progress) progress.style.display = "none";
      if (btn) btn.disabled = false;
      setStatus(`Fix All request failed: ${err.message}`, 'error');
      setStatus("Fix All request error", "error");
    }
  }

  function highlightDiffWords(oldStr, newStr) {
    if (oldStr === newStr) {
      return { oldHtml: escapeHtml(oldStr), newHtml: escapeHtml(newStr) };
    }
    // Tokenize into words (supports Latin, Devanagari, Bengali, Telugu, etc.), symbols, and whitespace
    const tokenize = s => s.match(/[\w\u0900-\u0D7F]+|[^\w\s\u0900-\u0D7F]+|\s+/g) || [s];
    const oldTokens = tokenize(oldStr);
    const newTokens = tokenize(newStr);

    let p = 0;
    while (p < oldTokens.length && p < newTokens.length && oldTokens[p] === newTokens[p]) {
      p++;
    }

    let s = 0;
    while (s < (oldTokens.length - p) && s < (newTokens.length - p) &&
      oldTokens[oldTokens.length - 1 - s] === newTokens[newTokens.length - 1 - s]) {
      s++;
    }

    const oldPre = oldTokens.slice(0, p).join('');
    const oldMid = oldTokens.slice(p, oldTokens.length - s).join('');
    const oldPost = oldTokens.slice(oldTokens.length - s).join('');

    const newPre = newTokens.slice(0, p).join('');
    const newMid = newTokens.slice(p, newTokens.length - s).join('');
    const newPost = newTokens.slice(newTokens.length - s).join('');

    return {
      oldHtml: escapeHtml(oldPre) + (oldMid ? '<mark class="diff-word-del">' + escapeHtml(oldMid) + '</mark>' : '') + escapeHtml(oldPost),
      newHtml: escapeHtml(newPre) + (newMid ? '<mark class="diff-word-ins">' + escapeHtml(newMid) + '</mark>' : '') + escapeHtml(newPost)
    };
  }

  function renderHunkRows(rows) {
    if (!rows || rows.length === 0) return '';
    const rowObjs = rows.map(r => ({ ...r }));

    let i = 0;
    while (i < rowObjs.length) {
      if (rowObjs[i].type === 'delete') {
        const delStart = i;
        while (i < rowObjs.length && rowObjs[i].type === 'delete') i++;
        const delEnd = i;
        const insStart = i;
        while (i < rowObjs.length && rowObjs[i].type === 'insert') i++;
        const insEnd = i;

        const delCount = delEnd - delStart;
        const insCount = insEnd - insStart;
        const pairCount = Math.min(delCount, insCount);

        for (let k = 0; k < pairCount; k++) {
          const d = rowObjs[delStart + k];
          const a = rowObjs[insStart + k];
          const diffRes = highlightDiffWords(d.text, a.text);
          d.renderedHtml = diffRes.oldHtml;
          a.renderedHtml = diffRes.newHtml;
        }
        for (let k = pairCount; k < delCount; k++) {
          rowObjs[delStart + k].renderedHtml = '<mark class="diff-word-del">' + escapeHtml(rowObjs[delStart + k].text) + '</mark>';
        }
        for (let k = pairCount; k < insCount; k++) {
          rowObjs[insStart + k].renderedHtml = '<mark class="diff-word-ins">' + escapeHtml(rowObjs[insStart + k].text) + '</mark>';
        }
      } else if (rowObjs[i].type === 'insert') {
        rowObjs[i].renderedHtml = '<mark class="diff-word-ins">' + escapeHtml(rowObjs[i].text) + '</mark>';
        i++;
      } else {
        rowObjs[i].renderedHtml = escapeHtml(rowObjs[i].text);
        i++;
      }
    }

    let html = '';
    for (const r of rowObjs) {
      const rowClass = r.type === 'delete' ? 'gh-diff-delete' : (r.type === 'insert' ? 'gh-diff-insert' : 'gh-diff-context');
      const marker = r.type === 'delete' ? '-' : (r.type === 'insert' ? '+' : ' ');
      const oldNum = (r.old_lineno !== null && r.old_lineno !== undefined) ? r.old_lineno : (r.old_num !== null && r.old_num !== undefined ? r.old_num : '');
      const newNum = (r.new_lineno !== null && r.new_lineno !== undefined) ? r.new_lineno : (r.new_num !== null && r.new_num !== undefined ? r.new_num : '');
      html += `<tr class="gh-diff-row ${rowClass}">
        <td class="gh-gutter gh-line-old">${oldNum}</td>
        <td class="gh-gutter gh-line-new">${newNum}</td>
        <td class="gh-gutter gh-marker">${marker}</td>
        <td class="gh-code"><code>${r.renderedHtml || escapeHtml(r.text)}</code></td>
      </tr>`;
    }
    return html;
  }

  function renderHunksHtml(hunks) {
    if (!hunks || hunks.length === 0) {
      return `<div style="padding: 12px; font-size: 12px; color: #57606a; font-style: italic;">No textual changes in this hunk.</div>`;
    }
    let tableHtml = '<div class="gh-diff-table-container"><table class="gh-diff-table"><tbody>';
    hunks.forEach((hunk, idx) => {
      if (idx > 0) {
        tableHtml += `<tr class="gh-hunk-divider"><td colspan="4">@@ -${hunk.old_start || 1} +${hunk.new_start || 1} @@</td></tr>`;
      }
      tableHtml += renderHunkRows(hunk.rows || []);
    });
    tableHtml += '</tbody></table></div>';
    return tableHtml;
  }

  function renderErrorSection(err, index) {
    const isFixed = err.fixed !== false;
    const errorNum = err.index || index;
    const title = err.title || err.rule_id || err.finding_id || `Error ${errorNum}`;
    const lineLabel = (err.line_start && err.line_end && err.line_start !== err.line_end)
      ? `lines ${err.line_start}-${err.line_end}`
      : `line ${err.line_start || 1}`;

    const isDet = (err.rule_or_source === "deterministic" || err.fix_type === "rule-based" || err.is_deterministic);
    let badgeHtml = "";
    if (isFixed) {
      if (isDet) {
        badgeHtml = `<span class="fix-badge-source badge-det">[deterministic fix]</span>`;
      } else {
        badgeHtml = `<span class="fix-badge-source badge-ai">[AI fix]</span>`;
      }
    } else if (err.status === "unverified" || (err.hunks && err.hunks.length > 0)) {
      badgeHtml = `<span class="fix-badge-source badge-manual" style="background:#FEF3C7; color:#92400E;">[unverified]</span>`;
    } else {
      badgeHtml = `<span class="fix-badge-source badge-manual">[unresolved]</span>`;
    }

    let bodyContent = "";
    if (isFixed) {
      bodyContent = renderHunksHtml(err.hunks || []);
    } else {
      const reason = err.reason || err.explanation || "Correction pending verification.";
      let hunksHtml = (err.hunks && err.hunks.length > 0) ? renderHunksHtml(err.hunks) : "";
      bodyContent = `
        <div class="gh-unfixed-reason-box">
          <span class="gh-unfixed-icon">⚠️</span>
          <div class="gh-unfixed-text">
            <strong>Unresolved diagnostic:</strong> ${escapeHtml(reason)}
          </div>
        </div>
        ${hunksHtml}
      `;
    }

    return `
      <div class="fix-error-card expanded ${isFixed ? '' : 'unfixed-card'}" data-error-index="${errorNum}">
        <div class="fix-error-card-header" role="button" tabindex="0">
          <div class="fix-error-header-main">
            <span class="fix-error-chevron">▼</span>
            <div class="fix-error-title-wrap">
              <span class="fix-error-number">Error ${errorNum}:</span>
              <span class="fix-error-title" title="${escapeHtml(title)}">${escapeHtml(title)}</span>
              <span class="fix-error-line-badge">${escapeHtml(lineLabel)}</span>
            </div>
          </div>
          <div class="fix-error-header-badges">
            ${badgeHtml}
          </div>
        </div>
        <div class="fix-error-card-body">
          ${bodyContent}
        </div>
      </div>
    `;
  }

  function buildErrorRecords(data, unresolved) {
    if (Array.isArray(data.error_diffs) && data.error_diffs.length > 0) {
      return data.error_diffs;
    }
    if (Array.isArray(data.error_records) && data.error_records.length > 0) {
      return data.error_records;
    }
    const records = [];
    let idx = 1;
    const applied = data.applied_fixes || data.fixes || [];
    for (const f of applied) {
      records.push({
        index: idx++,
        title: f.title || f.explanation || f.rule_id || 'Security issue',
        rule_or_source: (f.fix_type === 'rule-based' || f.is_deterministic) ? 'deterministic' : 'ai',
        line_start: f.target_line || (f.finding_data && f.finding_data.line) || 1,
        line_end: f.target_line || (f.finding_data && f.finding_data.line) || 1,
        before: f.original_code || '',
        after: f.proposed_code || '',
        hunks: f.hunks || [],
        fixed: true,
        rule_id: f.rule_id || '',
        finding_id: f.finding_id || '',
        explanation: f.explanation || ''
      });
    }
    const unres = data.manual_fixes || data.unresolved || unresolved || [];
    for (const u of unres) {
      records.push({
        index: idx++,
        title: u.title || u.rule_id || u.id || 'Unresolved diagnostic',
        rule_or_source: 'unresolved',
        line_start: u.line || u.target_line || 1,
        line_end: u.line || u.target_line || 1,
        before: '',
        after: '',
        hunks: u.hunks || [],
        fixed: false,
        reason: u.reason || u.explanation || 'Correction pending verification',
        rule_id: u.rule_id || '',
        finding_id: u.id || u.finding_id || '',
        explanation: u.explanation || ''
      });
    }
    return records;
  }

  function renderFixAllPerErrorView(data, unresolved) {
    const records = buildErrorRecords(data, unresolved);
    const fixedCount = records.filter(r => r.fixed !== false).length;
    const unfixedCount = records.length - fixedCount;

    let summaryText = "";
    if (unfixedCount === 0) {
      summaryText = `${fixedCount} error${fixedCount === 1 ? '' : 's'} fixed`;
    } else if (fixedCount === 0) {
      summaryText = `${unfixedCount} error${unfixedCount === 1 ? '' : 's'} could not be fixed`;
    } else {
      summaryText = `${fixedCount} error${fixedCount === 1 ? '' : 's'} fixed, ${unfixedCount} could not be fixed`;
    }

    let html = `
      <div class="fix-all-summary-bar">
        <div class="fix-all-summary-title">
          <span class="fix-summary-dot ${unfixedCount > 0 ? 'has-unfixed' : ''}"></span>
          <span>${escapeHtml(summaryText)}</span>
        </div>
        <button type="button" class="btn-toggle-all-sections" id="btn-toggle-all-diffs">Collapse all</button>
      </div>
      <div class="fix-error-cards-list" style="display: flex; flex-direction: column; gap: 10px;">
    `;

    records.forEach((rec, i) => {
      html += renderErrorSection(rec, i + 1);
    });

    html += `</div>`;
    return html;
  }

  function bindErrorSectionToggles(container) {
    if (!container) return;
    const headers = container.querySelectorAll(".fix-error-card-header");
    headers.forEach(h => {
      h.addEventListener("click", () => {
        const card = h.closest(".fix-error-card");
        if (card) {
          card.classList.toggle("expanded");
        }
      });
    });

    const toggleAllBtn = container.querySelector("#btn-toggle-all-diffs");
    if (toggleAllBtn) {
      toggleAllBtn.addEventListener("click", () => {
        const cards = container.querySelectorAll(".fix-error-card");
        const anyExpanded = Array.from(cards).some(c => c.classList.contains("expanded"));
        if (anyExpanded) {
          cards.forEach(c => c.classList.remove("expanded"));
          toggleAllBtn.textContent = "Expand all";
        } else {
          cards.forEach(c => c.classList.add("expanded"));
          toggleAllBtn.textContent = "Collapse all";
        }
      });
    }
  }

  function openFixAllModal(stageId, data, unresolved) {
    if (!elements.fixModalOverlay) return;
    if (typeof closeStageDrawer === "function") {
      closeStageDrawer();
    }

    const defn = state.pipeline.stages.find(s => s.id === stageId) || { name: stageId };
    const applied = data.applied_fixes || data.fixes || [];
    const resCount = data.resolved_count !== undefined ? data.resolved_count : applied.length;
    const totalCount = data.total_diagnostics !== undefined ? data.total_diagnostics : (applied.length + (unresolved ? unresolved.length : 0));
    if (totalCount === 0 && applied.length === 0) {
      return;
    }

    elements.fixModalTitle.textContent = `Fix All: ${defn.name} (${resCount}/${totalCount} Issues Resolved)`;
    if (resCount === 0) {
      elements.fixModalSeverity.style.display = "none";
    } else {
      elements.fixModalSeverity.style.display = "inline-flex";
      elements.fixModalSeverity.textContent = `${resCount} Issue${resCount > 1 ? 's' : ''} Fixed`;
      if (resCount < totalCount) {
        elements.fixModalSeverity.className = "fix-modal-badge sev-medium";
      } else {
        elements.fixModalSeverity.className = "fix-modal-badge sev-low";
      }
    }

    if (elements.fixModalSource) {
      const modelLabel = data.fixer_source || (data.model_selected ? (data.model_selected === "Deterministic" ? "Deterministic" : `Gemini (${data.model_selected})`) : "Deterministic");
      elements.fixModalSource.textContent = modelLabel;
      elements.fixModalSource.className = "fix-modal-source-badge badge-gemini-ai";
    }
    if (elements.fixModalValidation) {
      let vText = "Not fixed";
      let vClass = "val-failed";
      if (data.validation_badge_text) {
        vText = data.validation_badge_text;
        vClass = data.validation_badge_class || (vText === "Verified Clean" ? "val-passed" : (vText === "Partially fixed" ? "val-partial" : "val-failed"));
      } else {
        if (resCount > 0 && (data.remaining_count === 0 || resCount === totalCount)) {
          vText = "Verified Clean";
          vClass = "val-passed";
        } else if (resCount > 0 && resCount < totalCount) {
          vText = "Partially fixed";
          vClass = "val-partial";
        } else {
          vText = "Not fixed";
          vClass = "val-failed";
        }
      }
      elements.fixModalValidation.textContent = vText;
      elements.fixModalValidation.className = `fix-modal-val-badge ${vClass}`;
    }
    if (elements.fixAiRefiningBar) {
      elements.fixAiRefiningBar.style.display = "none";
    }

    if (elements.fixModalCard) {
      elements.fixModalCard.classList.add("fix-all-mode");
    }

    // Hide legacy single diff preview elements in Fix All mode
    if (elements.fixModalExplanation) {
      elements.fixModalExplanation.style.display = "none";
    }
    const resultsPanel = document.getElementById("fix-modal-results-panel");
    if (resultsPanel) {
      resultsPanel.style.display = "none";
    }
    const viewModes = document.querySelector(".diff-view-modes");
    if (viewModes) {
      viewModes.style.display = "none";
    }
    const diffContainerUnified = document.getElementById("diff-container-unified");
    if (diffContainerUnified) {
      diffContainerUnified.style.display = "none";
    }
    const diffContainerSplit = document.getElementById("diff-container-split");
    if (diffContainerSplit) {
      diffContainerSplit.style.display = "none";
    }

    // Render per-error unified diff list
    if (elements.fixModalPerErrorContainer) {
      elements.fixModalPerErrorContainer.style.display = "flex";
      elements.fixModalPerErrorContainer.innerHTML = renderFixAllPerErrorView(data, unresolved);
      bindErrorSectionToggles(elements.fixModalPerErrorContainer);
    }

    const unverified = data.manual_fixes || data.unresolved || [];
    const hasUnverifiedCandidate = unverified.some(u => u.candidate_source || (u.hunks && u.hunks.length > 0));

    if (applied.length > 0) {
      elements.btnApplyFix.disabled = false;
      elements.btnApplyFix.textContent = `Apply ${applied.length} Fix${applied.length > 1 ? 'es' : ''}`;
    } else if (hasUnverifiedCandidate) {
      elements.btnApplyFix.disabled = false;
      elements.btnApplyFix.textContent = "Apply anyway (unverified)";
    } else if (data.ai_online !== false) {
      elements.btnApplyFix.disabled = false;
      elements.btnApplyFix.textContent = "Retry with AI";
    } else {
      elements.btnApplyFix.disabled = false;
      elements.btnApplyFix.textContent = "Retry";
    }
    if (elements.btnRejectFix) {
      elements.btnRejectFix.textContent = "Cancel";
    }

    // Suspect Fix Warning Banner (Requirement 3)
    if (elements.fixModalSuspectWarning) {
      if (data.is_suspect || data.suspect) {
        if (elements.fixModalSuspectText) {
          const wText = data.suspect_warnings && data.suspect_warnings.length
            ? data.suspect_warnings.join("; ")
            : (data.suspect_warning || "Warning: Suspect fix detected — a flagged line was deleted or replaced rather than remediated.");
          elements.fixModalSuspectText.textContent = wText;
        }
        elements.fixModalSuspectWarning.style.display = "flex";
      } else {
        elements.fixModalSuspectWarning.style.display = "none";
      }
    }

    state.security.pendingFix = {
      is_fix_all: true,
      is_initial_view: false,
      revision_id: data.revision_id,
      proposed_hash: data.proposed_hash,
      stage_id: stageId,
      target_stage_id: stageId,
      source_revision: state.sourceRevisionId || 1,
      file_path: state.currentFile ? state.currentFile.path : "",
      proposed_source: data.proposed_source,
      diff: data.diff,
      delta_text: data.delta_text,
      is_suspect: Boolean(data.is_suspect || data.suspect),
      suspect_warning: data.suspect_warning,
      suspect_warnings: data.suspect_warnings,
      resolved_count: resCount,
      total_diagnostics: totalCount,
      explanation: data.explanation || "",
      fixes: applied,
      unresolved: data.unresolved || unresolved || []
    };

    updateUndoButtonsState();
    elements.fixModalOverlay.style.display = "flex";
  }

  let aiFixRerunAbortController = null;
  let aiFixRerunOriginalSource = null;

  async function startAiFixAndRerunLoop() {
    if (!state.currentFile) return;
    if (!elements.aiFixRerunModalOverlay) return;

    aiFixRerunOriginalSource = state.editor.getValue();
    aiFixRerunAbortController = new AbortController();

    elements.aiFixRerunModalOverlay.style.display = "flex";
    if (elements.btnPipelineAiFixStop) elements.btnPipelineAiFixStop.style.display = "inline-flex";
    if (elements.btnPipelineAiFixRerun) elements.btnPipelineAiFixRerun.style.display = "none";

    elements.aiFixRerunStatusBadge.textContent = "Running";
    elements.aiFixRerunStatusBadge.className = "fix-modal-badge badge-warning";
    elements.aiFixRerunIterationLogs.innerHTML = "<div style='color:var(--text-muted);'>Initiating multi-stage repair loop...</div>";
    elements.aiFixRerunSummarySection.style.display = "none";
    elements.btnAiFixRerunUndo.style.display = "none";
    elements.btnAiFixRerunSave.disabled = true;

    try {
      const resp = await fetch("/api/pipeline/ai-fix-and-rerun", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: aiFixRerunAbortController.signal,
        body: JSON.stringify({
          code: state.editor.getValue(),
          language: state.currentFile.language || "English",
          file_path: state.currentFile.path || "",
          category: state.currentFile.category || "",
          use_ai: state.useAiSecurity
        })
      });

      const data = await resp.json();
      renderAiFixRerunResults(data);
    } catch (err) {
      if (err.name === "AbortError") {
        elements.aiFixRerunStatusBadge.textContent = "Stopped by user";
        elements.aiFixRerunStatusBadge.className = "fix-modal-badge badge-idle";
        elements.aiFixRerunIterationLogs.innerHTML += `<div style="color:#F59E0B; margin-top:8px;">Execution halted by user request.</div>`;
      } else {
        elements.aiFixRerunStatusBadge.textContent = "Error";
        elements.aiFixRerunStatusBadge.className = "fix-modal-badge badge-failed";
        elements.aiFixRerunIterationLogs.innerHTML += `<div style="color:#EF4444; margin-top:8px;">Loop failed: ${escapeHtml(err.message)}</div>`;
      }
    } finally {
      if (elements.btnPipelineAiFixStop) elements.btnPipelineAiFixStop.style.display = "none";
      updateAiFixRerunButtonVisibility(state.pipeline.status);
    }
  }

  function renderAiFixRerunResults(data) {
    if (!data) return;

    if (data.proposed_source && data.proposed_source !== state.editor.getValue()) {
      state.editor.setValue(data.proposed_source);
      state.isDirty = true;
      updateTabModifiedIndicator();
    }

    if (data.iteration_logs && data.iteration_logs.length > 0) {
      elements.aiFixRerunIterationLogs.innerHTML = data.iteration_logs
        .map(l => `<div style="padding: 2px 0;">${escapeHtml(l)}</div>`)
        .join("");
    } else {
      elements.aiFixRerunIterationLogs.innerHTML = "<div>No iterations logged.</div>";
    }

    const passed = Boolean(data.success || data.passed);
    elements.aiFixRerunStatusBadge.textContent = passed ? "Completed" : (data.final_status || "Stopped");
    elements.aiFixRerunStatusBadge.className = passed ? "fix-modal-badge badge-completed" : "fix-modal-badge badge-failed";

    elements.aiFixRerunSummarySection.style.display = "block";
    const issuesFixedStr = Object.entries(data.issues_fixed_per_stage || {})
      .map(([k, v]) => `${k.replace(/_/g, ' ')}: ${v}`)
      .join(", ") || "0 issues";

    elements.aiFixRerunStatsPills.innerHTML = `
      <span class="finding-score-badge" style="background:#1E293B; color:#94A3B8; padding: 4px 8px; border-radius: 4px;">Iterations: ${data.iterations_count || 0}/6</span>
      <span class="finding-score-badge" style="background:${passed ? '#065F46' : '#7F1D1D'}; color:#fff; padding: 4px 8px; border-radius: 4px;">Status: ${escapeHtml(data.final_status || (passed ? 'COMPLETED' : 'FAILED'))}</span>
      <span class="finding-score-badge" style="background:#1E293B; color:#94A3B8; padding: 4px 8px; border-radius: 4px;">Issues Fixed: ${escapeHtml(issuesFixedStr)}</span>
      ${data.stop_reason ? `<span class="finding-score-badge" style="background:#1E293B; color:#CBD5E1; padding: 4px 8px; border-radius: 4px;">${escapeHtml(data.stop_reason)}</span>` : ''}
    `;

    if (data.is_suspect && data.suspect_fixes && data.suspect_fixes.length > 0) {
      elements.aiFixRerunSuspectBanner.style.display = "block";
      elements.aiFixRerunSuspectBanner.innerHTML = `⚠️ <strong>Suspect Fix Detected:</strong> ${escapeHtml(data.suspect_fixes.join("; "))}`;
    } else {
      elements.aiFixRerunSuspectBanner.style.display = "none";
    }

    elements.aiFixRerunDiffPre.textContent = data.whole_buffer_diff || "(No modifications made to code buffer)";

    if (data.undo_available && aiFixRerunOriginalSource) {
      elements.btnAiFixRerunUndo.style.display = "inline-flex";
      elements.btnAiFixRerunUndo.onclick = () => {
        state.editor.setValue(aiFixRerunOriginalSource);
        state.isDirty = false;
        updateTabModifiedIndicator();
        runHealthAnalysis(true);
        executePipelineRun();
        elements.btnAiFixRerunUndo.style.display = "none";
      };
    } else {
      elements.btnAiFixRerunUndo.style.display = "none";
    }

    elements.btnAiFixRerunSave.disabled = !passed;
    elements.btnAiFixRerunSave.onclick = () => {
      if (!passed) return;
      handleSaveFile();
      closeAiFixRerunModal();
    };

    executePipelineRun();
  }

  function closeAiFixRerunModal() {
    if (elements.aiFixRerunModalOverlay) {
      elements.aiFixRerunModalOverlay.style.display = "none";
    }
    if (aiFixRerunAbortController) {
      aiFixRerunAbortController.abort();
      aiFixRerunAbortController = null;
    }
  }

  async function handleSuggestFixClick(findingId, stageId) {
    const container = document.getElementById(`inline-remediation-${findingId}`);
    if (!container) return;

    const finding = getStageFindings(stageId).find(f => String(f.id) === String(findingId)) ||
      (state.security.findings || []).find(f => String(f.id) === String(findingId)) || { id: findingId };

    // Set loading indicator indicating Gemini AI consultation
    container.innerHTML = `
      <div class="inline-remediation-box">
        <div style="display: flex; align-items: center; gap: 8px; color: #2563EB; font-size: 12px;">
          <span class="ai-spin-icon">⟳</span>
          <span>AI Analysis Running (Routing to Gemini AI) for <strong>${escapeHtml(finding.title || findingId)}</strong>...</span>
        </div>
      </div>
    `;
    setStatus("AI Analysis Running...", "running");

    const currentCode = state.editor ? state.editor.getValue() : "";
    const lang = state.currentFile ? state.currentFile.language : "English";

    try {
      const resp = await sourceRequest("/api/security/suggest-fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code: currentCode,
          finding_id: findingId,
          finding: finding,
          stage_id: stageId,
          language: lang,
          source_revision: state.sourceRevisionId || 1,
          file_path: state.currentFile ? state.currentFile.path : "",
          prefer_deterministic: true,
          request_ai: false
        })
      });
      const res = await resp.json();
      res.target_finding_id = findingId;
      res.source_revision = state.sourceRevisionId || 1;
      res.file_path = state.currentFile ? state.currentFile.path : "";
      state.findingFixes[findingId] = res;
      setStatus(`Correction Generated (${res.model_selected || 'Gemini AI'})`, "running");

      if (res.success && res.proposed_source && res.proposed_source !== currentCode) {
        if (state.findingsStore && state.findingsStore[findingId]) {
          state.findingsStore[findingId].status = "fix_proposed";
        }
        renderInlineRemediation(findingId, stageId, res);
      } else {
        const errorMsg = (res.proposed_source === currentCode)
          ? "No code changes detected in proposed fix."
          : (res.error || "Automated patch could not be validated.");
        const isOffline = res.ai_online === false || res.ollama_online === false;
        container.innerHTML = `
          <div class="inline-remediation-box" style="border-left: 3px solid #EF4444;">
            <div style="font-size: 12px; color: #991B1B;">
              <strong>${isOffline ? 'Gemini AI Offline:' : 'AI Remediation Note:'}</strong> ${escapeHtml(errorMsg)}
            </div>
            <div style="font-size: 11.5px; color: #475569; margin-top: 4px;">
              ${escapeHtml(finding.remediation || 'Please review the stage diagnostic and apply manual correction if necessary.')}
            </div>
            <button class="btn btn-secondary btn-sm" id="btn-close-inline-${findingId}" style="align-self: flex-start; margin-top: 4px;">Dismiss</button>
          </div>
        `;
        const dBtn = document.getElementById(`btn-close-inline-${findingId}`);
        if (dBtn) dBtn.addEventListener("click", () => { container.innerHTML = ""; });
      }
    } catch (err) {
      container.innerHTML = `
        <div class="inline-remediation-box" style="border-left: 3px solid #EF4444;">
          <div style="font-size: 12px; color: #991B1B;">Remediation request error: ${escapeHtml(err.message)}</div>
        </div>
      `;
    }
  }

  function renderInlineRemediation(findingId, stageId, fixData) {
    const container = document.getElementById(`inline-remediation-${findingId}`);
    if (!container) return;

    const isDet = Boolean(fixData.is_deterministic);
    const sourceLabel = isDet ? "Local Rule" : "Gemini AI";
    const sourceBadgeClass = isDet ? "badge-local-rule" : "badge-gemini-ai";

    const rawDiff = fixData.diff || `--- original\n+++ proposed\n- ${fixData.original_code}\n+ ${fixData.proposed_code}`;
    const diffLines = rawDiff.split("\n");
    let diffHtml = "";
    diffLines.forEach(l => {
      const esc = escapeHtml(l);
      if (l.startsWith("+") && !l.startsWith("+++")) {
        diffHtml += `<span class="diff-add">${esc}</span>\n`;
      } else if (l.startsWith("-") && !l.startsWith("---")) {
        diffHtml += `<span class="diff-del">${esc}</span>\n`;
      } else if (l.startsWith("@")) {
        diffHtml += `<span class="diff-info">${esc}</span>\n`;
      } else {
        diffHtml += `${esc}\n`;
      }
    });

    const hasUndo = Boolean(state.security.undoStack && state.security.undoStack.length > 0);

    const valStatusLabel = fixData.validation_status || "Validated — Resolves Error";
    const valStatusClass = (valStatusLabel.toLowerCase().includes("validated") || valStatusLabel.toLowerCase().includes("passed")) ? "val-passed" : "val-not-tested";

    const modelBadge = fixData.model_selected ? `<span class="fix-modal-source-badge badge-gemini-ai" style="font-size: 10px;">🤖 ${escapeHtml(fixData.model_selected)}</span>` : '';
    const escBadge = fixData.is_escalated ? `<span class="fix-modal-badge sev-low" style="font-size: 10px; background: #FEF3C7; color: #92400E;">⚡ Escalated 7B</span>` : '';
    const timingHtml = fixData.timing ? `
      <div style="font-size: 11px; color: #475569; margin-top: 4px; display: flex; gap: 8px; flex-wrap: wrap;">
        <span><strong>Inference:</strong> ${fixData.timing.inference_time_ms || 0}ms</span>
        <span><strong>Validation:</strong> ${fixData.timing.compiler_validation_time_ms || 0}ms</span>
        <span><strong>Total:</strong> ${fixData.timing.total_duration_ms || 0}ms</span>
        ${fixData.tokens_per_second ? `<span><strong>Speed:</strong> ${fixData.tokens_per_second} tok/s</span>` : ''}
      </div>
    ` : '';

    container.innerHTML = `
      <div class="inline-remediation-box" id="box-inline-${escapeHtml(findingId)}">
        <div class="inline-remediation-header">
          <div style="display: flex; align-items: center; gap: 6px; flex-wrap: wrap;">
            <span style="font-weight: 700; color: #0F172A;">✨ AI Fix Available:</span>
            <span class="fix-modal-source-badge ${sourceBadgeClass}">${sourceLabel}</span>
            ${modelBadge}
            ${escBadge}
            <span class="fix-modal-val-badge ${valStatusClass}">${escapeHtml(valStatusLabel)}</span>
          </div>
          <button class="btn btn-secondary btn-sm" id="btn-reject-inline-${escapeHtml(findingId)}" style="font-size: 11px; padding: 2px 7px;">✕ Dismiss</button>
        </div>

        ${fixData.identified_root_cause || fixData.root_cause ? `<div style="font-size: 12px; color: #1E293B; margin-bottom: 3px;"><strong>Root Cause:</strong> ${escapeHtml(fixData.identified_root_cause || fixData.root_cause)}</div>` : ''}
        ${fixData.routing_reason ? `<div style="font-size: 11px; color: #4338CA; margin-bottom: 3px;"><strong>Routing:</strong> ${escapeHtml(fixData.routing_reason)}</div>` : ''}

        <div style="font-size: 12px; color: #334155; line-height: 1.45;">
          <strong>Explanation:</strong> ${escapeHtml(fixData.explanation || 'Applies targeted remediation to resolve this diagnostic.')}
        </div>

        ${fixData.expected_effect ? `<div style="font-size: 11.5px; color: #047857; margin-top: 3px;"><strong>Expected Validation:</strong> ${escapeHtml(fixData.expected_effect)}</div>` : ''}

        ${timingHtml}

        <div style="font-size: 11px; font-weight: 600; color: #64748B; text-transform: uppercase; margin-top: 4px;">
          Unified Diff Preview (Changes to Working Buffer):
        </div>
        <div class="inline-diff-preview">${diffHtml}</div>

        <div class="inline-remediation-actions" style="margin-top: 6px;">
          <button class="btn btn-primary btn-sm" id="btn-apply-inline-${escapeHtml(findingId)}" style="background: #2563EB; border-color: #1D4ED8; font-weight: 700;">
            <span>✓ Apply AI Fix / Approve Fix</span>
          </button>
          <button class="btn btn-secondary btn-sm" id="btn-full-diff-${escapeHtml(findingId)}">
            <span>🔍 Full Diff Modal</span>
          </button>
          ${hasUndo ? `<button class="btn btn-secondary btn-sm" id="btn-undo-inline-${escapeHtml(findingId)}"><span>↩ Undo Fix</span></button>` : ''}
        </div>
      </div>
    `;

    const applyBtn = document.getElementById(`btn-apply-inline-${findingId}`);
    if (applyBtn) {
      applyBtn.addEventListener("click", () => handleApplyInlineFix(findingId, stageId, fixData));
    }

    const rejectBtn = document.getElementById(`btn-reject-inline-${findingId}`);
    if (rejectBtn) {
      rejectBtn.addEventListener("click", () => {
        container.innerHTML = "";
        delete state.findingFixes[findingId];
      });
    }

    const fullDiffBtn = document.getElementById(`btn-full-diff-${findingId}`);
    if (fullDiffBtn) {
      fullDiffBtn.addEventListener("click", () => {
        const finding = getStageFindings(stageId).find(f => String(f.id) === String(findingId)) || { id: findingId };
        openFixModal(findingId, finding);
      });
    }

    const undoBtn = document.getElementById(`btn-undo-inline-${findingId}`);
    if (undoBtn) {
      undoBtn.addEventListener("click", () => {
        undoLastSecurityFix();
      });
    }
  }

  async function handleApplyInlineFix(findingId, stageId, fixData) {
    if (!fixData || !fixData.proposed_source) return;
    const currentCode = state.editor ? state.editor.getValue() : "";
    const proposedCode = fixData.proposed_source;
    const lang = state.currentFile ? state.currentFile.language : "English";

    // Validate proposal freshness and identity
    if (proposedCode === currentCode) {
      setStatus("Status: Already applied.", "ready");
      runCompiler(null, true);
      return;
    }
    if (fixData.revision_id !== await revisionOf(currentCode) || (fixData.source_revision && fixData.source_revision !== state.sourceRevisionId)) {
      setStatus("Source changed since this fix was suggested, regenerating...", "running");
      delete state.findingFixes[findingId];
      const container = document.getElementById(`inline-remediation-${findingId}`);
      if (container) container.innerHTML = "";
      handleSuggestFixClick(findingId, stageId, fixData.finding_data || { id: findingId });
      return;
    }
    if (fixData.file_path && state.currentFile && fixData.file_path !== state.currentFile.path) {
      setStatus("This fix belongs to a different file. Please re-generate the fix for the active file.", "warning");
      return;
    }

    // 3. Atomically apply and persist fix via backend /api/ai/apply-fix
    try {
      const applyResp = await sourceRequest("/api/ai/apply-fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          file_path: (state.currentFile && state.currentFile.path) || fixData.file_path || "",
          code: proposedCode, preview_revision: fixData.revision_id, proposed_hash: fixData.proposed_hash,
          source_revision: state.sourceRevisionId,
          stage_id: stageId || "syntax_analysis",
          language: lang,
          finding_id: findingId
        })
      });
      const applyData = await applyResp.json();
      if (applyData.status === "already_applied") {
        setStatus("Status: Already applied.", "ready");
        runCompiler(null, true);
        return;
      }
      if (applyData.status === "stale_revision" || (!applyData.success && applyData.error && applyData.error.includes("Source changed since this fix was suggested"))) {
        setStatus("Source changed since this fix was suggested, regenerating...", "running");
        delete state.findingFixes[findingId];
        handleSuggestFixClick(findingId, stageId, fixData.finding_data || { id: findingId });
        return;
      }
      if (!applyResp.ok || !applyData.success) {
        setStatus("Patch Rejected: " + (applyData.error || "Validation failed"), "error");
        const container = document.getElementById(`inline-remediation-${findingId}`);
        if (container) {
          container.innerHTML = `
            <div class="repair-failure-banner" style="background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #fecaca; padding: 8px; border-radius: 4px; font-size: 12px;">
              <span>✕ Patch Application Rejected: ${escapeHtml(applyData.error || "Validation failed.")}</span>
            </div>
          `;
        }
        state.editor.setValue(currentCode);
        saveCurrentFileBuffer();
        return;
      }
      state.editor.setValue(proposedCode);
      updateUndoButtonsState(true);
      saveCurrentFileBuffer();
      state.sourceRevisionId = applyData.source_revision || (state.sourceRevisionId + 1);
    } catch (err) {
      setStatus("Failed to communicate with compiler backend: " + err.message, "error");
      state.editor.setValue(currentCode);
      saveCurrentFileBuffer();
      return;
    }

    // 4. Mark target finding as pending revalidation
    if (state.findingsStore && state.findingsStore[findingId]) {
      state.findingsStore[findingId].status = "pending_validation";
      state.findingsStore[findingId].validation_status = "validating";
    }
    delete state.findingFixes[findingId];

    // 5. Mark applied in inline container
    const container = document.getElementById(`inline-remediation-${findingId}`);
    if (container) {
      container.innerHTML = `
        <div class="repair-success-banner">
          <span>✓ Fix applied and persisted to backend (rev ${state.sourceRevisionId})! Revalidating compiler pipeline...</span>
        </div>
      `;
    }
    elements.tabDirtyIndicator.classList.add("visible");
    setStatus(`Status: Fix for ${findingId} applied and persisted to disk. Re-verifying...`, "running");

    // 6. Invalidate all stages for new revision and auto re-run compilation
    invalidateAllStagesForNewRevision(state.sourceRevisionId);
    setStatus(`Status: Applied Revision ${state.sourceRevisionId}. Re-verifying stage security & pipeline...`, "running");
    await runCompiler(null, true);
  }

  const CANONICAL_STAGE_IDS = [
    "source_input", "lexical_analysis", "syntax_analysis", "ast_construction",
    "semantic_analysis", "symbol_table", "ir_generation", "optimization",
    "code_generation", "code_validation", "security_analysis", "ai_security_analysis",
    "sandbox_execution", "final_report"
  ];

  function computeHeaderStatusFromStages() {
    const stageIds = CANONICAL_STAGE_IDS;
    const stageData = state.pipeline.stageData || {};
    let hasRunning = false;
    let hasPending = false;
    let hasFailed = false;
    let hasBlocked = false;
    let hasWarning = false;
    let hasUnavailable = false;
    let hasSecurityBlocked = false;

    for (const sid of stageIds) {
      const st = stageData[sid];
      const stStatus = st ? String(st.status).toLowerCase() : "pending";
      if (stStatus === "pending") hasPending = true;
      else if (stStatus === "running") hasRunning = true;
      else if (stStatus === "failed") {
        hasFailed = true;
        if (sid === "security_analysis") hasSecurityBlocked = true;
      } else if (stStatus === "blocked") {
        hasBlocked = true;
        const reason = (st && (st.skip_reason || st.summary)) || "";
        if (reason.toLowerCase().includes("stage 11") || reason.toLowerCase().includes("security policy") || reason.toLowerCase().includes("sast policy")) {
          hasSecurityBlocked = true;
        }
      } else if (stStatus === "warning") hasWarning = true;
      else if (stStatus === "unavailable") hasUnavailable = true;
    }

    const firstFailedStage = stageIds.find(sid => stageData[sid] && stageData[sid].status === "failed");
    if (firstFailedStage && firstFailedStage !== "security_analysis" && firstFailedStage !== "ai_security_analysis") {
      hasSecurityBlocked = false;
    }

    if (state.isExecuting && (hasRunning || hasPending)) {
      return "RUNNING";
    }
    if (hasSecurityBlocked) return "BLOCKED BY SECURITY";
    if (hasFailed || hasBlocked) return "FAILED";
    if (hasUnavailable) return "INCOMPLETE";
    if (hasWarning) return "WARNING";
    return "COMPLETED";
  }

  function ensureHeaderStatusMatchesFinalStages() {
    if (!elements.pipelineStatusBadge) return;
    const badgeText = elements.pipelineStatusBadge.textContent.trim().toUpperCase();
    if (badgeText === "RUNNING") {
      const computed = computeHeaderStatusFromStages();
      if (computed !== "RUNNING") {
        elements.pipelineStatusBadge.textContent = computed;
        const norm = computed.toLowerCase().replace(/ /g, "_");
        elements.pipelineStatusBadge.className = `pipeline-status-badge badge-${norm}`;
      }
    }
  }

  async function recoverRunFinishViaRest(runId) {
    if (!runId) return false;
    try {
      const resp = await fetch(`/api/runs/${encodeURIComponent(runId)}`, {
        headers: { "X-Session-ID": state.sessionId || "" }
      });
      if (!resp.ok) return false;
      const data = await resp.json();
      if (!data || !data.success) return false;

      const finishEvent = {
        event: "pipeline_finish",
        run_id: data.run_id || runId,
        source_hash: data.source_hash || state.currentBufferHash,
        revision_id: data.source_revision || state.pipeline.revisionHash,
        status: data.status || data.overall_status || "completed",
        overall_status: data.overall_status || data.status || "completed",
        header_message: data.header_message || (data.status === "completed" ? "All 14 stages completed successfully" : `Pipeline finished: ${data.status}`),
        progress_pct: data.progress_pct !== undefined ? data.progress_pct : 100,
        completed_count: data.completed_count !== undefined ? data.completed_count : 14,
        applicable_count: data.applicable_count || 14,
        elapsed_ms: data.elapsed_ms || 0,
        stages: data.stages || data.stage_table || [],
        artifacts: data.artifacts || {},
        issues: data.issues || [],
        counts_by_stage: data.counts_by_stage || {},
        counts_by_severity: data.counts_by_severity || {},
        total_fixable: data.total_fixable || 0
      };
      console.log("[run] recovered finish via REST", finishEvent);
      handlePipelineEvent(finishEvent);
      return true;
    } catch (e) {
      console.error("[run] failed to recover finish via REST:", e);
      return false;
    }
  }

  /* ========================================================================
     4. COMPILER EXECUTION (RUN BUTTON) WITH LIVE STREAMING PIPELINE
     ======================================================================== */
  async function runCompiler(resumeFromStage = null, autoResume = false, isOverride = false) {
    if (state.isExecuting && !autoResume) return;

    const sourceCode = state.editor.getValue().trim();
    if (!sourceCode) {
      setStatus("Status: Error - Empty Source Code", "error");
      elements.consoleProgram.textContent = "> Error: No source code provided. Please enter or select code to run.";
      return;
    }

    state.isExecuting = true;
    setRunningUI(true);
    if (elements.healthFixDelta) {
      elements.healthFixDelta.style.display = "none";
    }

    // Generate unique UUID run ID (Requirement 1)
    state.runCounter = (state.runCounter || 0) + 1;
    const runSeq = state.runCounter;
    const runId = (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function")
      ? crypto.randomUUID()
      : ("run-" + Date.now() + "-" + Math.random().toString(36).substring(2, 10));
    state.pipeline.activeRunId = runId;
    state.pipeline.activeRunSeq = runSeq;
    state.pipeline.hasReceivedEventForRun = false;
    state.pipeline.compiledSource = state.editor.getValue();
    state.currentBufferHash = sha256Sync(state.pipeline.compiledSource);
    state.pipeline.activeSourceHash = state.currentBufferHash;
    try {
      if (typeof sessionStorage !== "undefined") {
        sessionStorage.setItem("vital_active_run_id", runId);
      }
    } catch (e) { }
    state.securityResults = {};
    state.pipeline.revisionHash = await revisionOf(state.pipeline.compiledSource);
    state.pipeline.isReportGenerated = false;
    state.pipeline.isReadyForReport = false;
    state.pipeline.isFinished = false;
    state.pipeline.finishStatus = null;
    state.pipeline.pendingArtifacts = null;
    state.pipeline.isPaused = false;
    state.pipeline.pausedStage = null;
    state.pipeline.blockingStageId = null;
    state.pipeline.runRevision = state.sourceRevisionId || 1;

    if (!resumeFromStage) {
      // Requirement 1: On Run, first fetch (or reuse, if the hash matches the current buffer) the Code Health result.
      const currentRawSource = state.editor ? state.editor.getValue() : sourceCode;
      const currentHash = sha256Sync(currentRawSource);
      let healthData = (state.codeHealth && state.codeHealth.source_hash === currentHash) ? state.codeHealth : null;
      if (!healthData) {
        try {
          const resp = await fetch("/api/health/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              source: currentRawSource,
              language: state.currentFile ? state.currentFile.language : (state.currentLanguage || "english"),
              filename: (state.currentFile && state.currentFile.filename) || state.currentFilename || "script.vital"
            })
          });
          if (resp.ok) {
            healthData = await resp.json();
            state.codeHealth = healthData;
            renderHealthChip(healthData);
            renderHealthPanel(healthData);
            renderHealthGutterMarkers(healthData);
          }
        } catch (err) {
          console.warn("[preflight] failed to fetch health on run:", err);
        }
      }
      state.activePreflightHealth = healthData;
      if (healthData) {
        renderPreflightStrip(healthData);
      }

      resetPipelineStepper(true);
      resetProgressiveTabs();
      switchOutputTab("tab-out-program");
      if (elements.outputWaitingState) elements.outputWaitingState.style.display = "none";
      if (elements.outputTabsBar) elements.outputTabsBar.style.display = "flex";
      if (elements.outputContentArea) elements.outputContentArea.style.display = "block";
      const emptyState = document.getElementById("output-blocked-empty-state");
      if (emptyState) emptyState.style.display = "none";
      const incompBanner = document.getElementById("pipeline-report-incomplete-banner");
      if (incompBanner) incompBanner.style.display = "none";
      if (elements.consoleProgram) {
        elements.consoleProgram.style.display = "block";
        elements.consoleProgram.textContent = "Waiting for Stage 13…\n";
      }
      if (elements.consolePipeline) {
        elements.consolePipeline.textContent = "Waiting for Stage 14…\n";
      }
      if (elements.consoleLexer) elements.consoleLexer.textContent = "";
      if (elements.consoleParser) elements.consoleParser.textContent = "";
      if (elements.consoleAst) elements.consoleAst.textContent = "";
      if (elements.consoleIr) elements.consoleIr.textContent = "";
      if (elements.consoleSymbol) elements.consoleSymbol.textContent = "";
      if (elements.consoleOptimization) elements.consoleOptimization.textContent = "";
      if (elements.btnPipelineSaveCorrected) {
        elements.btnPipelineSaveCorrected.disabled = true;
        elements.btnPipelineSaveCorrected.style.opacity = "0.5";
      }
      switchOutputTab("tab-out-program");
      setStatus(isOverride ? "Status: Running Pipeline with Security Override (Sandbox)..." : "Status: Running Compiler & Security Pipeline...", "running");
    } else {
      invalidateDownstreamStages(resumeFromStage);
      const emptyState = document.getElementById("output-blocked-empty-state");
      if (emptyState) emptyState.style.display = "none";
      const incompBanner = document.getElementById("pipeline-report-incomplete-banner");
      if (incompBanner) incompBanner.style.display = "none";
      if (elements.consoleProgram) {
        elements.consoleProgram.style.display = "block";
        elements.consoleProgram.textContent = "Waiting for Stage 13…\n";
      }
      if (elements.consolePipeline) {
        elements.consolePipeline.textContent = "Waiting for Stage 14…\n";
      }
      const resumeNode = document.getElementById(`step-node-${resumeFromStage}`);
      if (resumeNode) {
        resumeNode.className = "stepper-step status-running";
        const icon = resumeNode.querySelector(".stepper-step-icon");
        if (icon) icon.textContent = "⟳";
      }
      setStatus(`Status: Automatically resuming pipeline from ${resumeFromStage}...`, "running");
    }

    let watchdogInterval = null;
    try {
      watchdogInterval = setInterval(async () => {
        if (state.pipeline.isFinished) {
          clearInterval(watchdogInterval);
          return;
        }
        const stages = state.pipeline.stageData || {};
        const allFinal = CANONICAL_STAGE_IDS.every(sid => {
          const s = stages[sid];
          return s && s.status && s.status !== "pending" && s.status !== "running";
        });
        if (allFinal && runId) {
          console.warn("[run] Watchdog detected all stages final but pipeline unfinished; recovering via REST...");
          clearInterval(watchdogInterval);
          await recoverRunFinishViaRest(runId);
        }
      }, 5000);

      // Connect to SSE stream
      const resp = await sourceRequest("/api/pipeline/stream", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Session-ID": state.sessionId || ""
        },
        body: JSON.stringify({
          run_id: runId,
          source_hash: state.currentBufferHash,
          session_id: state.sessionId,
          code: state.editor.getValue(),
          language: state.currentFile.language,
          use_ai_security: elements.toggleStage12Ai ? elements.toggleStage12Ai.checked : false,
          pause_on_error: true,
          resume_from: resumeFromStage || undefined,
          source_revision: state.sourceRevisionId || 1,
          override: isOverride,
          security_override: isOverride
        })
      });

      if (!resp.ok) {
        throw new Error(`Server returned HTTP ${resp.status}`);
      }

      if (resp.body && typeof resp.body.getReader === "function") {
        const reader = resp.body.getReader();
        const decoder = new TextDecoder("utf-8");
        let buffer = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const parts = buffer.split(/\r?\n\r?\n/);
          buffer = parts.pop() || "";

          for (const part of parts) {
            const lines = part.split(/\r?\n/);
            for (const line of lines) {
              const trimmed = line.trim();
              if (trimmed.startsWith("data:")) {
                const jsonStr = trimmed.substring(5).trim();
                if (jsonStr) {
                  let event = null;
                  try {
                    event = JSON.parse(jsonStr);
                  } catch (parseErr) {
                    console.warn("[SSE] JSON parse error:", parseErr);
                  }
                  if (event) {
                    try {
                      handlePipelineEvent(event);
                    } catch (handlerErr) {
                      console.error("[SSE] Error in handlePipelineEvent:", handlerErr);
                    }
                    await new Promise(r => requestAnimationFrame(r));
                  }
                }
              }
            }
          }
        }

        // Drain any leftover event in the buffer
        if (buffer && buffer.trim()) {
          const lines = buffer.split(/\r?\n/);
          for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.startsWith("data:")) {
              const jsonStr = trimmed.substring(5).trim();
              if (jsonStr) {
                let event = null;
                try {
                  event = JSON.parse(jsonStr);
                } catch (parseErr) {
                  console.warn("[SSE] JSON parse error in remainder:", parseErr);
                }
                if (event) {
                  try {
                    handlePipelineEvent(event);
                  } catch (handlerErr) {
                    console.error("[SSE] Error in handlePipelineEvent:", handlerErr);
                  }
                  await new Promise(r => requestAnimationFrame(r));
                }
              }
            }
          }
        }

        // Self-healing check: if stream ended without a terminal event, recover via REST
        if (!state.pipeline.isFinished && runId) {
          console.warn("[run] stream closed without terminal event; recovering via REST for", runId);
          await recoverRunFinishViaRest(runId);
        }
      } else {
        // Fallback for environments lacking streaming response readers
        const fallbackResp = await sourceRequest("/api/pipeline/run", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Session-ID": state.sessionId || ""
          },
          body: JSON.stringify({
            run_id: runId,
            source_hash: state.currentBufferHash,
            session_id: state.sessionId,
            code: state.editor.getValue(),
            language: state.currentFile.language,
            use_ai_security: true,
            pause_on_error: true,
            resume_from: resumeFromStage || undefined,
            source_revision: state.sourceRevisionId || 1,
            override: isOverride,
            security_override: isOverride
          })
        });
        const fallbackData = await fallbackResp.json();
        if (fallbackData) {
          if (fallbackData.stages && Array.isArray(fallbackData.stages)) {
            fallbackData.stages.forEach(st => {
              handlePipelineEvent({
                run_id: fallbackData.run_id || runId,
                event: `stage_${st.status}`,
                stage_id: st.id,
                stage: st.name,
                stage_status: st.status,
                progress_pct: fallbackData.progress_pct,
                completed_count: fallbackData.completed_count,
                applicable_count: fallbackData.applicable_count || 14,
                elapsed_ms: st.duration_ms,
                summary: st.summary,
                duration_ms: st.duration_ms,
                findings_count: st.findings_count,
                skip_reason: st.skip_reason
              });
            });
          }
          handlePipelineEvent({
            run_id: fallbackData.run_id || runId,
            event: "pipeline_finish",
            status: fallbackData.status || fallbackData.final_status || "failed",
            artifacts: fallbackData.artifacts,
            progress_pct: fallbackData.progress_pct || 100,
            completed_count: fallbackData.completed_count || 0,
            applicable_count: fallbackData.applicable_count || 14
          });
        }
      }

    } catch (err) {
      console.error("Execution error:", err);
      let recovered = false;
      if (!state.pipeline.isFinished && runId) {
        try {
          console.warn("[run] error encountered; attempting REST recovery for", runId);
          recovered = await recoverRunFinishViaRest(runId);
        } catch (recErr) {
          console.error("[run] REST recovery exception:", recErr);
        }
      }
      if (!recovered) {
        setStatus("Status: Fatal Connection Error", "error");
        elements.consoleProgram.textContent = `[SYSTEM ERROR]\nFailed to communicate with compiler backend: ${err.message}`;
        if (elements.pipelineStatusBadge) {
          elements.pipelineStatusBadge.textContent = "ERROR";
          elements.pipelineStatusBadge.className = "pipeline-status-badge badge-failed";
        }
        if (elements.pipelineProgressFill) {
          elements.pipelineProgressFill.classList.add("fill-failed");
        }
        if (elements.pipelineMetricStage) {
          elements.pipelineMetricStage.innerHTML = `Run result could not be loaded — <button id="btn-header-retry-run" class="btn btn-sm btn-secondary" style="padding: 2px 8px; font-size: 11px; margin-left: 6px; cursor: pointer;">Retry</button>`;
          const retryBtn = document.getElementById("btn-header-retry-run");
          if (retryBtn) {
            retryBtn.onclick = () => {
              const runBtn = document.getElementById("btn-run");
              if (runBtn) runBtn.click();
            };
          }
        }
      }
    } finally {
      if (watchdogInterval) {
        clearInterval(watchdogInterval);
      }
      state.isExecuting = false;
      setRunningUI(false);
      ensureHeaderStatusMatchesFinalStages();
    }
  }

  function handleExecutionResult(res) {
    if (!res) return;
    // 1. Timing
    elements.outputTimingBadge.textContent = `${res.elapsed_ms || 0} ms`;
    elements.statusbarElapsed.textContent = `${res.elapsed_ms || 0} ms`;

    // Override Warning Banner
    const banner = document.getElementById("override-warning-banner");
    if (banner) {
      if (res.security_override || (res.output && res.output.includes("EXECUTED WITH SECURITY OVERRIDE"))) {
        banner.style.display = "block";
      } else {
        banner.style.display = "none";
      }
    }

    const isIncomplete = Boolean(res.incomplete);
    const isBlocked = Boolean(res.blocking_stage_id || res.security_blocked || state.pipeline.isPaused || (isIncomplete && (!res.output && res.execution_status !== "completed")));

    // 2. Output and Blocked State Handling
    if (isBlocked) {
      let bSid = res.blocking_stage_id;
      if (!bSid && Array.isArray(res.stages)) {
        const nonPassed = res.stages.find(s => s && (s.status === "failed" || s.status === "unavailable" || s.status === "blocked"));
        if (nonPassed) bSid = nonPassed.id;
      }
      if (!bSid && state.pipeline.stageData) {
        const stageOrder = ["source_input", "lexical_analysis", "syntax_analysis", "ast_construction", "semantic_analysis", "symbol_table", "ir_generation", "optimization", "code_generation", "code_validation", "security_analysis", "ai_security_analysis", "sandbox_execution", "final_report"];
        for (const sid of stageOrder) {
          const data = state.pipeline.stageData[sid];
          if (data && (data.status === "failed" || data.status === "unavailable" || data.status === "blocked")) {
            bSid = sid;
            break;
          }
        }
      }
      if (!bSid) {
        bSid = state.pipeline.blockingStageId || "execution";
      }
      const bNum = res.blocking_stage_num || (STAGE_INFO_NUM[bSid] || 0);
      const bName = res.blocking_stage_name || (STAGE_INFO_NAME[bSid] || bSid);
      const bReason = res.blocking_reason || (isIncomplete ? "Pipeline incomplete: Stage 12 unavailable." : "Execution blocked by stage gate policy.");
      const isSecBlocked = (bSid === "security_analysis" || bSid === "ai_security_analysis" || res.security_blocked);
      showOutputBlockedState(bSid, bNum, bName, bReason, isSecBlocked);
    } else {
      const emptyState = document.getElementById("output-blocked-empty-state");
      if (emptyState) emptyState.style.display = "none";
      const incompBanner = document.getElementById("pipeline-report-incomplete-banner");
      if (incompBanner) {
        incompBanner.style.display = res.incomplete ? "block" : "none";
      }
      if (elements.consoleProgram) {
        elements.consoleProgram.style.display = "block";
        elements.consoleProgram.textContent = (res.output && res.output.trim()) ? res.output : "(Program produced no output)";
      }
      if (elements.btnPipelineSaveCorrected) {
        elements.btnPipelineSaveCorrected.disabled = false;
        elements.btnPipelineSaveCorrected.style.opacity = "1";
      }
    }

    // 3. Populate tabs strictly for completed artifacts
    elements.consolePipeline.textContent = res.aggregated_log || res.parser_log || "(No pipeline report generated)";

    if (res.lexer_log) {
      elements.consoleLexer.textContent = res.lexer_log;
      revealStageTab("lexical_analysis");
    } else {
      elements.consoleLexer.textContent = "";
      if (isIncomplete) hideStageTab("lexical_analysis");
    }

    if (res.parser_log) {
      elements.consoleParser.textContent = res.parser_log;
      revealStageTab("syntax_analysis");
    } else {
      elements.consoleParser.textContent = "";
      if (isIncomplete) hideStageTab("syntax_analysis");
    }

    if (res.ast_log) {
      elements.consoleAst.textContent = res.ast_log;
      revealStageTab("ast_construction");
    } else {
      elements.consoleAst.textContent = "";
      if (isIncomplete) hideStageTab("ast_construction");
    }

    if (res.symbol_table) {
      elements.consoleSymbol.textContent = res.symbol_table;
      revealStageTab("semantic_analysis");
      revealStageTab("symbol_table");
    } else {
      elements.consoleSymbol.textContent = "";
      if (isIncomplete) {
        hideStageTab("semantic_analysis");
        hideStageTab("symbol_table");
      }
    }

    if (res.ir_code) {
      elements.consoleIr.textContent = res.ir_code;
      revealStageTab("ir_generation");
    } else {
      elements.consoleIr.textContent = "";
      if (isIncomplete) hideStageTab("ir_generation");
    }

    if (elements.consoleOptimization) {
      if (res.optimization) {
        const opt = res.optimization;
        const optText = [
          "================================================================================",
          "               MANDATORY IR OPTIMIZATION REPORT & PROOF LOG                     ",
          "================================================================================",
          `• Optimization Status:   ${(opt.status || "completed").toUpperCase()}`,
          `• Passes Attempted:      ${(opt.passes_attempted || []).join(", ") || "Constant Folding, Constant Propagation, Algebraic Simplification, Redundant Op Elimination, Dead Code Elimination"}`,
          `• Passes Applied:        ${(opt.passes_applied || []).join(", ") || "None (IR was already optimal)"}`,
          `• Transformations:       ${opt.transformations_count !== undefined ? opt.transformations_count : 0} applied`,
          `• IR Validation:         ${opt.validation_status || "PASSED"}`,
          `• Optimizer Summary:     ${opt.summary || "Completed successfully."}`,
          opt.ai_analysis ? `• Gemini AI Review:      ${opt.ai_analysis}` : "",
          "--------------------------------------------------------------------------------",
          "OPTIMIZATION TRANSFORMATIONS APPLIED:",
          (opt.transformations && opt.transformations.length > 0)
            ? opt.transformations.map(t => `  [Line ${t.line}] (${t.pass}): ${t.description}`).join("\n")
            : "  (No transformations required — original IR is already canonically optimal)",
          "--------------------------------------------------------------------------------",
          "OPTIMIZED INTERMEDIATE REPRESENTATION (PYTHON IR):",
          opt.optimized_ir || res.ir_code || "(No optimized IR)",
          "================================================================================"
        ].filter(Boolean).join("\n");
        elements.consoleOptimization.textContent = optText;
        revealStageTab("optimization");
      } else {
        elements.consoleOptimization.textContent = "";
        if (isIncomplete) hideStageTab("optimization");
      }
    }

    // Clear existing error badges on tabs
    elements.outputTabBtns.forEach(b => b.classList.remove("error-badge"));

    // Status and Diagnostics
    if (res.success && !isIncomplete) {
      setStatus(`Status: System Ready | Compilation Succeeded`, "ready");
      switchOutputTab("tab-out-program");
    } else {
      setStatus(`Status: Compilation Blocked or Incomplete`, "error");
      if (res.execution_status === "syntax_error") {
        const parserBtn = document.querySelector('[data-tab="tab-out-parser"]');
        if (parserBtn) parserBtn.classList.add("error-badge");
      }
      switchOutputTab("tab-out-program");
    }
  }

  /* ========================================================================
     SECURITY ANALYSIS & GEMINI AI AGENT WORKFLOW
     ======================================================================== */
  async function checkAIStatus() {
    try {
      let resp = await fetch("/api/ai/status");
      let data = {};
      if (resp.ok) {
        data = await resp.json();
      } else {
        resp = await fetch("/api/security/status");
        data = await resp.json();
      }
      const isOnline = Boolean(data.ok !== undefined ? data.ok : (data.ai_online !== undefined ? data.ai_online : data.ollama_online));
      const modelName = data.model || (data.config && data.config.model_name) || "gemini-flash-lite-latest";
      const statusMsg = data.reason || data.message || "";

      state.security.aiStatus = {
        online: isOnline,
        model: modelName,
        message: statusMsg
      };

      const lbl = elements.aiStatusLabel || elements.ollamaStatusLabel || document.getElementById("ai-status-label");
      const dot = elements.aiPulseDot || elements.ollamaPulseDot || document.getElementById("ai-pulse-dot");
      const container = elements.aiStatusIndicator || elements.ollamaStatusIndicator || document.getElementById("ai-status-indicator");

      if (lbl && dot) {
        if (isOnline) {
          lbl.textContent = "Gemini ready";
          dot.className = "status-pulse-dot";
          if (container) container.title = `Gemini ready (${modelName})`;
        } else {
          const reason = statusMsg || "Service unavailable";
          lbl.textContent = `Gemini unavailable: ${reason}`;
          dot.className = "status-pulse-dot offline";
          if (container) container.title = `Gemini unavailable: ${reason}`;
        }
      }
    } catch (e) {
      const lbl = elements.aiStatusLabel || elements.ollamaStatusLabel || document.getElementById("ai-status-label");
      const dot = elements.aiPulseDot || elements.ollamaPulseDot || document.getElementById("ai-pulse-dot");
      const container = elements.aiStatusIndicator || elements.ollamaStatusIndicator || document.getElementById("ai-status-indicator");
      if (lbl && dot) {
        lbl.textContent = "Gemini unavailable: Network error";
        dot.className = "status-pulse-dot offline";
        if (container) container.title = "Gemini unavailable: Network error";
      }
    }
  }
  const checkOllamaSecurityStatus = checkAIStatus;

  async function runSecurityScan(useAi = true) {
    const code = state.editor.getValue();
    if (!code || !code.trim()) {
      renderSecurityFindings([], 0, "No code in editor to analyze.", false);
      return;
    }

    try {
      setStatus("Status: Running Security Analysis...", "running");
      const resp = await sourceRequest("/api/security/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code: code,
          language: state.currentFile.language,
          use_ai: useAi
        })
      });
      const data = await resp.json();

      if (data.success) {
        const fname = (state.currentFile && state.currentFile.name) || "source.vital";
        const contentHash = data.content_hash || "unknown";
        const findingsCount = (data.findings || []).length;
        console.log(`[Stage 11] scanning ${fname} @ ${contentHash} -> ${findingsCount} issues found`);

        renderSecurityFindings(
          data.findings || [],
          data.overall_risk_score,
          data.overall_summary || "",
          Boolean(data.syntax_blocked)
        );
        const scoreDisplay = data.syntax_blocked ? "BLOCKED" : `${data.overall_risk_score}/100`;
        setStatus(`Status: Security Scan Complete (${data.total_findings} finding(s), Risk: ${scoreDisplay})`, "ready");
      }
    } catch (err) {
      console.error("Security scan error:", err);
      setStatus("Status: Security Scan Error", "error");
    }
  }

  function renderSecurityFindings(findings, overallScore, summary, syntaxBlocked = false) {
    state.security.findings = findings || [];
    state.security.overallScore = overallScore;

    const isBlocked = Boolean(syntaxBlocked || overallScore === "BLOCKED");

    // 1. Update Score Circle
    if (elements.securityScoreVal) {
      elements.securityScoreVal.textContent = isBlocked ? "BLOCKED" : (typeof overallScore === "number" ? overallScore : 0);
    }
    const scoreLabel = elements.securityScoreCircle ? elements.securityScoreCircle.querySelector(".security-score-label") : null;
    if (scoreLabel) {
      scoreLabel.textContent = isBlocked ? "INCOMPLETE" : "RISK SCORE";
    }

    if (elements.securityScoreCircle) {
      elements.securityScoreCircle.className = "security-score-circle";
      if (isBlocked) {
        elements.securityScoreCircle.classList.add("score-blocked");
      } else {
        const numScore = typeof overallScore === "number" ? overallScore : 0;
        if (numScore >= 85) elements.securityScoreCircle.classList.add("score-crit");
        else if (numScore >= 65) elements.securityScoreCircle.classList.add("score-high");
        else if (numScore >= 40) elements.securityScoreCircle.classList.add("score-med");
        else if (numScore >= 20) elements.securityScoreCircle.classList.add("score-low");
        else elements.securityScoreCircle.classList.add("score-clean");
      }
    }

    // 2. Tab Risk Pill
    if (elements.securityTabRiskPill) {
      if (isBlocked) {
        elements.securityTabRiskPill.textContent = "BLOCKED";
        elements.securityTabRiskPill.className = "security-risk-pill risk-pill-blocked";
      } else {
        const numScore = typeof overallScore === "number" ? overallScore : 0;
        elements.securityTabRiskPill.textContent = numScore;
        elements.securityTabRiskPill.className = "security-risk-pill " + (numScore > 0 ? "risk-pill-warn" : "risk-pill-clean");
      }
    }

    // 3. Verdict (Clean scan must strictly state "No issues detected by enabled checks", never "100% secure")
    if (elements.securityVerdict) {
      if (isBlocked) {
        elements.securityVerdict.textContent = summary || "Assessment Incomplete: Syntax errors prevented downstream analysis.";
      } else if (!findings || findings.length === 0) {
        elements.securityVerdict.textContent = "No issues detected by enabled checks.";
      } else {
        elements.securityVerdict.textContent = summary || "Vulnerabilities detected by security scanner.";
      }
    }

    // 4. Severity Pills Count
    const safeFindings = findings || [];
    const critCount = safeFindings.filter(f => f.severity === "Critical").length;
    const highCount = safeFindings.filter(f => f.severity === "High").length;
    const medCount = safeFindings.filter(f => f.severity === "Medium").length;
    const lowCount = safeFindings.filter(f => f.severity === "Low").length;

    if (elements.pillCountCrit) elements.pillCountCrit.textContent = `${critCount} Critical`;
    if (elements.pillCountHigh) elements.pillCountHigh.textContent = `${highCount} High`;
    if (elements.pillCountMed) elements.pillCountMed.textContent = `${medCount} Med`;
    if (elements.pillCountLow) elements.pillCountLow.textContent = `${lowCount} Low`;

    // 5. Findings List Display
    if (elements.securityEmptyState && elements.securityFindingsList) {
      if (safeFindings.length === 0 && !isBlocked) {
        elements.securityEmptyState.style.display = "flex";
        elements.securityFindingsList.style.display = "none";
        elements.securityFindingsList.innerHTML = "";
      } else {
        elements.securityEmptyState.style.display = "none";
        elements.securityFindingsList.style.display = "flex";
        elements.securityFindingsList.innerHTML = "";

        if (isBlocked) {
          const blockedCard = document.createElement("div");
          blockedCard.className = "security-finding-card severity-Critical";
          blockedCard.innerHTML = `
            <div class="finding-card-header">
              <div class="finding-badges-left">
                <span class="finding-id-badge">SEC-BLOCKED</span>
                <span class="finding-sev-badge sev-Critical">PIPELINE BLOCKED</span>
                <span class="finding-cat-badge">Syntax Dependency</span>
              </div>
            </div>
            <div class="finding-title-row">Assessment Incomplete: Syntax Errors Prevented Analysis</div>
            <div class="finding-expl-text">
              The AST, Semantic, Symbol Table, and Security scanners cannot reliably evaluate code with unbalanced delimiters or unparseable syntax. Resolve parser errors in Stage 3 to unblock downstream security assessment.
            </div>
          `;
          elements.securityFindingsList.appendChild(blockedCard);
        }

        safeFindings.forEach(f => {
          const card = document.createElement("div");
          card.className = `security-finding-card severity-${f.severity || 'Medium'}`;

          const locStr = f.line ? `Line ${f.line}${f.column ? `, Col ${f.column}` : ''}` : "";

          // Taint flow data path visualization
          let taintFlowHtml = "";
          if (f.source_sink_flow && (f.source_sink_flow.source || f.source_sink_flow.sink)) {
            const src = f.source_sink_flow.source || "User Input";
            const inter = f.source_sink_flow.intermediate ? `<span class="taint-step-node">${escapeHtml(f.source_sink_flow.intermediate)}</span><span class="taint-arrow">➔</span>` : "";
            const sink = f.source_sink_flow.sink || "Sink Operation";
            taintFlowHtml = `
              <div class="taint-flow-box">
                <div class="taint-flow-header">
                  <span>🌊 Taint Analysis Data Flow</span>
                </div>
                <div class="taint-flow-steps">
                  <span class="taint-step-node step-source">Source: ${escapeHtml(src)}</span>
                  <span class="taint-arrow">➔</span>
                  ${inter}
                  <span class="taint-step-node step-sink">Sink: ${escapeHtml(sink)}</span>
                </div>
              </div>
            `;
          }

          card.innerHTML = `
            <div class="finding-card-header">
              <div class="finding-badges-left">
                <span class="finding-id-badge">${escapeHtml(f.id)}</span>
                <span class="finding-sev-badge sev-${f.severity}">${escapeHtml(f.severity)}</span>
                ${f.defect_category ? `<span class="finding-cat-badge">${escapeHtml(f.defect_category)}</span>` : ''}
                <span class="finding-score-badge">Weight: ${f.risk_score || 0}/100</span>
                <span class="finding-stage-tag">${escapeHtml(f.stage || 'Security Scan')}</span>
              </div>
              <span class="finding-status-tag" title="Verification Status">${escapeHtml(f.confidence || 'confirmed rule match')}</span>
            </div>
            
            <div class="finding-title-row">
              <span>${escapeHtml(f.title)}</span>
              ${f.line ? `<button class="finding-loc-btn" data-line="${f.line}" data-col="${f.column || 1}" title="Click to navigate to line in editor">📍 ${locStr}</button>` : ''}
            </div>

            ${f.code_excerpt ? `<pre class="finding-source-excerpt"><code>${escapeHtml(f.code_excerpt)}</code></pre>` : (f.evidence ? `<div class="finding-evidence-box"><code>${escapeHtml(f.evidence)}</code></div>` : '')}

            <div class="finding-expl-text">${escapeHtml(f.explanation)}</div>

            ${f.potential_impact ? `
              <div class="potential-impact-box">
                <span class="impact-label">Potential Impact:</span>
                <span>${escapeHtml(f.potential_impact)}</span>
              </div>
            ` : ''}

            ${taintFlowHtml}

            ${f.remediation ? `
              <div class="finding-remediation-box">
                <span class="remediation-label">Recommended Correction:</span>
                <span>${escapeHtml(f.remediation)}</span>
              </div>
            ` : ''}

            <div class="finding-card-footer">
              <span style="font-size: 11px; color: var(--text-dim);">Rule ID: ${escapeHtml(f.rule_id || f.id)}</span>
              <div style="display: flex; gap: 6px;">
                <button class="btn btn-primary btn-sm btn-suggest-fix" data-finding-id="${escapeHtml(f.id)}">
                  <span>✨ Suggest Fix</span>
                </button>
              </div>
            </div>
          `;

          // Bind click to line navigation
          const locBtn = card.querySelector(".finding-loc-btn");
          if (locBtn) {
            locBtn.addEventListener("click", () => {
              const line = parseInt(locBtn.getAttribute("data-line"), 10);
              const col = parseInt(locBtn.getAttribute("data-col"), 10) || 1;
              if (state.editor && line > 0) {
                state.editor.setCursor(line - 1, Math.max(0, col - 1));
                state.editor.focus();
                const lineHandle = state.editor.addLineClass(line - 1, "background", "cm-line-highlight");
                setTimeout(() => {
                  state.editor.removeLineClass(lineHandle, "background", "cm-line-highlight");
                }, 2000);
              }
            });
          }

          const fixBtn = card.querySelector(".btn-suggest-fix");
          if (fixBtn) {
            fixBtn.addEventListener("click", () => openFixModal(f.id, f));
          }

          elements.securityFindingsList.appendChild(card);
        });
      }
    }
  }

  function updateUndoButtonsState(persisted) {
    if (typeof persisted === "boolean") state.security.persistedUndo = persisted;
    const hasUndo = Boolean(state.security.persistedUndo || state.security.undoStack.length);
    if (elements.btnUndoFix) elements.btnUndoFix.disabled = !hasUndo;
    if (elements.btnUndoEditorFix) elements.btnUndoEditorFix.disabled = !hasUndo;
    if (elements.btnModalUndoFix) elements.btnModalUndoFix.style.display = hasUndo ? "inline-flex" : "none";
  }

  function switchDiffViewMode(mode) {
    if (mode === "unified") {
      if (elements.btnModeUnified) elements.btnModeUnified.classList.add("active");
      if (elements.btnModeSplit) elements.btnModeSplit.classList.remove("active");
      if (elements.diffContainerUnified) elements.diffContainerUnified.style.display = "block";
      if (elements.diffContainerSplit) elements.diffContainerSplit.style.display = "none";
    } else {
      if (elements.btnModeUnified) elements.btnModeUnified.classList.remove("active");
      if (elements.btnModeSplit) elements.btnModeSplit.classList.add("active");
      if (elements.diffContainerUnified) elements.diffContainerUnified.style.display = "none";
      if (elements.diffContainerSplit) elements.diffContainerSplit.style.display = "grid";
    }
  }

  function openOriginalViewModal() {
    if (!elements.originalModalOverlay) return;
    const path = state.currentFile ? state.currentFile.path : "";
    const original = (state.fileStore[path] && state.fileStore[path].originalCode !== undefined)
      ? state.fileStore[path].originalCode
      : (state.currentFile ? state.currentFile.originalCode : "");

    if (elements.originalModalPath) elements.originalModalPath.textContent = path || "Current Program";
    if (elements.originalModalCode) elements.originalModalCode.textContent = original || "// No original source available";
    elements.originalModalOverlay.style.display = "flex";
    resetPipelineFullState("view_original_open");
  }

  function closeOriginalViewModal() {
    if (elements.originalModalOverlay) {
      elements.originalModalOverlay.style.display = "none";
    }
    resetPipelineFullState("view_original_close");
  }

  async function restoreOriginalDemo() {
    if (!state.currentFile || !state.currentFile.path) return;
    const path = state.currentFile.path;
    const original = (state.fileStore[path] && state.fileStore[path].originalCode !== undefined)
      ? state.fileStore[path].originalCode
      : state.currentFile.originalCode;

    const currentVal = state.editor.getValue();
    if (original !== undefined && currentVal !== original) {
      const ok = confirm("Discard working buffer changes and restore the exact original educational demo?\n\n(A snapshot of your current edits will be saved to Undo)");
      if (!ok) return;
    }

    // 1. Save snapshot to undo stack first so user never loses work
    state.security.undoStack.push({
      code: currentVal,
      timestamp: Date.now(),
      label: "Before Restore Original",
      findingsStore: JSON.parse(JSON.stringify(state.findingsStore || {}))
    });
    updateUndoButtonsState();

    try {
      const resp = await fetch("/api/working-source/restore-original", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: path })
      });
      const data = await resp.json();
      if (data.success) {
        const pristine = data.original_source || data.working_source || original;
        state.editor.setValue(pristine);
        elements.tabDirtyIndicator.classList.remove("visible");

        state.sourceRevisionId = data.source_revision || 1;
        state.contentHash = data.content_hash || "";
        if (state.pipeline) {
          state.pipeline.sourceRevisionId = state.sourceRevisionId;
          state.pipeline.compiledSource = null;
          state.pipeline.isReportGenerated = false;
          state.pipeline.isReadyForReport = false;
          state.pipeline.pendingArtifacts = null;
          state.pipeline.stageData = {};
        }

        if (state.fileStore[path]) {
          state.fileStore[path].workingBuffer = pristine;
          state.fileStore[path].originalCode = pristine;
          state.fileStore[path].isDirty = false;
          state.fileStore[path].source_revision = state.sourceRevisionId;
          state.fileStore[path].content_hash = state.contentHash;
          persistWorkingBuffersToStorage();
        }

        state.findingsStore = {};
        state.findingFixes = {};
        resetPipelineFullState("restore_original");
        updateTabModifiedIndicator();
        updateSaveButtonState();
        runHealthAnalysis(true);
        showOutputWaitingState(
          "Original Educational Demo Restored",
          "All corrections discarded. Click ▶ Run to execute the compiler and observe the original errors/vulnerabilities."
        );
        closeOriginalViewModal();
        closeStageDrawer();
        updateUndoButtonsState(Boolean(data.can_undo));
        setStatus(`Status: Restored original educational demo (${state.currentFile.filename}).`, "ready");
        return;
      }
    } catch (e) {
      console.warn("Backend restore-original error, using local fallback:", e);
    }

    // Fallback to local pristine original
    if (original !== undefined) {
      state.editor.setValue(original);
      elements.tabDirtyIndicator.classList.remove("visible");
      if (state.fileStore[path]) {
        state.fileStore[path].workingBuffer = original;
        state.fileStore[path].isDirty = false;
        persistWorkingBuffersToStorage();
      }
      state.findingsStore = {};
      state.findingFixes = {};
      resetPipelineFullState("restore_original");
      updateTabModifiedIndicator();
      updateSaveButtonState();
      runHealthAnalysis(true);
      closeOriginalViewModal();
      closeStageDrawer();
      setStatus(`Status: Restored original demo (${state.currentFile.filename}).`, "ready");
    }
  }

  async function saveCorrectedCode() {
    const currentCode = state.editor ? state.editor.getValue() : "";
    if (!currentCode.trim()) {
      setStatus("Cannot save an empty file.", "warning");
      return;
    }

    const isVerified = isBufferVerifiedForSave();
    if (!isVerified) {
      const ok = confirm(
        "WARNING: The current code in the editor has NOT been verified by a complete pipeline run (Stages 1–12).\n\n" +
        "Saving unverified code may preserve syntax errors, semantic failures, or active security vulnerabilities.\n\n" +
        "Do you want to proceed and save this UNVERIFIED code anyway?"
      );
      if (!ok) return;
    }

    const origFilename = (state.currentFile && state.currentFile.filename) || "program.vital";
    const defaultFixedName = origFilename.endsWith(".vital")
      ? origFilename.replace(/\.vital$/, "_fixed.vital")
      : (origFilename + "_fixed.vital");

    const userFilename = prompt("Enter a filename to save your corrected program:", defaultFixedName);
    if (!userFilename) return;

    let cleanFilename = userFilename.trim();
    if (!cleanFilename.endsWith(".vital")) {
      cleanFilename += ".vital";
    }

    try {
      setStatus(`Saving corrected program as ${cleanFilename}...`, "running");
      const resp = await fetch("/api/save-file", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          filename: cleanFilename,
          code: currentCode
        })
      });
      const res = await resp.json();
      if (!res.success) {
        setStatus(`Failed to save file: ${res.error || 'Server rejected save request.'}`, "error");
        return;
      }

      setStatus(`Successfully saved ${cleanFilename} to My Saved Programs!`, "ready");

      // Refresh demo tree so new file appears in Explorer
      await loadDemosList();

      // Switch editor to the newly saved file
      if (res.path) {
        await loadDemoFile(res.path);
      }
    } catch (err) {
      console.error("Save file error:", err);
      setStatus(`Error saving file: ${err.message}`, "error");
    }
  }

  async function openFixModal(findingId, findingData) {
    if (!elements.fixModalOverlay) return;

    if (elements.fixModalCard) {
      elements.fixModalCard.classList.remove("fix-all-mode");
    }
    if (elements.fixModalPerErrorContainer) {
      elements.fixModalPerErrorContainer.style.display = "none";
      elements.fixModalPerErrorContainer.innerHTML = "";
    }
    const viewModes = document.querySelector(".diff-view-modes");
    if (viewModes) viewModes.style.display = "";
    if (elements.fixModalExplanation) elements.fixModalExplanation.style.display = "";
    const resultsPanel = document.getElementById("fix-modal-results-panel");
    if (resultsPanel) resultsPanel.style.display = "none";
    const diffContainerUnified = document.getElementById("diff-container-unified");
    if (diffContainerUnified) diffContainerUnified.style.display = "";
    if (elements.btnRejectFix) elements.btnRejectFix.textContent = "Reject / Close";

    elements.fixModalTitle.textContent = `Remediation for ${findingData.title || findingId}`;
    elements.fixModalSeverity.textContent = findingData.severity || "Warning";
    elements.fixModalSeverity.className = `fix-modal-badge sev-${findingData.severity || 'Medium'}`;

    if (elements.fixModalSource) {
      elements.fixModalSource.textContent = "Local rule";
      elements.fixModalSource.className = "fix-modal-source-badge badge-local-rule";
    }
    if (elements.fixModalValidation) {
      elements.fixModalValidation.textContent = "Not yet validated";
      elements.fixModalValidation.className = "fix-modal-val-badge val-not-tested";
    }
    if (elements.fixAiRefiningBar) {
      elements.fixAiRefiningBar.style.display = "none";
    }

    // Reset view modes to unified
    switchDiffViewMode("unified");
    elements.fixModalExplanation.textContent = "Evaluating safe deterministic rules (<2ms)...";
    elements.fixDiffPreview.textContent = "// Computing proposed diff...";
    if (elements.fixSplitBefore) elements.fixSplitBefore.textContent = "";
    if (elements.fixSplitAfter) elements.fixSplitAfter.textContent = "";
    elements.btnApplyFix.disabled = true;

    updateUndoButtonsState();
    elements.fixModalOverlay.style.display = "flex";

    const currentCode = state.editor.getValue();

    try {
      // 1. Request fast deterministic fix first (<2ms, cached, no UI freeze)
      const resp = await sourceRequest("/api/security/suggest-fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code: currentCode,
          finding_id: findingId,
          finding: findingData,
          language: state.currentFile.language,
          prefer_deterministic: true,
          request_ai: false
        })
      });

      const res = await resp.json();
      res.target_finding_id = findingId;
      res.source_revision = state.sourceRevisionId || 1;
      res.file_path = state.currentFile ? state.currentFile.path : "";
      state.security.pendingFix = res;

      if (res.success) {
        elements.fixModalExplanation.textContent = res.explanation || "Review the proposed unified diff below:";
        elements.btnApplyFix.disabled = false;

        const isDet = Boolean(res.is_deterministic);
        if (elements.fixModalSource) {
          elements.fixModalSource.textContent = isDet ? "Local rule" : "Gemini AI";
          elements.fixModalSource.className = `fix-modal-source-badge ${isDet ? 'badge-local-rule' : 'badge-gemini-ai'}`;
        }

        renderDiffPreview(res.diff || `--- original\n+++ proposed\n- ${res.original_code}\n+ ${res.proposed_code}`);
        if (elements.fixSplitBefore) elements.fixSplitBefore.textContent = res.original_code || currentCode;
        if (elements.fixSplitAfter) elements.fixSplitAfter.textContent = res.proposed_code || res.proposed_source || "";

        // 2. Non-blocking Progressive AI Refinement if Gemini is online and refinement is possible
        const aiStatusObj = state.security.aiStatus || state.security.ollamaStatus;
        if (res.can_refine_with_ai && aiStatusObj && aiStatusObj.online) {
          if (elements.fixAiRefiningBar) {
            if (elements.fixAiRefiningText) {
              elements.fixAiRefiningText.textContent = `Gemini (${aiStatusObj.model}) is refining suggestion in background...`;
            }
            elements.fixAiRefiningBar.style.display = "flex";
          }

          // Fire non-blocking request with timeout
          sourceRequest("/api/security/refine-fix", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              code: currentCode,
              finding_id: findingId,
              finding: findingData,
              current_fix: res,
              language: state.currentFile.language
            })
          }).then(async r => {
            const refined = await r.json();
            // Ensure modal is still open, still showing this finding, and pendingFix not already replaced
            if (elements.fixModalOverlay.style.display !== "none" &&
              state.security.pendingFix &&
              state.security.pendingFix.target_finding_id === findingId &&
              refined.success &&
              refined.improved) {

              refined.target_finding_id = findingId;
              refined.source_revision = state.sourceRevisionId || 1;
              refined.file_path = state.currentFile ? state.currentFile.path : "";
              state.security.pendingFix = refined;
              elements.fixModalExplanation.textContent = refined.explanation || elements.fixModalExplanation.textContent;
              if (elements.fixModalSource) {
                elements.fixModalSource.textContent = "Gemini AI (Refined)";
                elements.fixModalSource.className = "fix-modal-source-badge badge-gemini-ai";
              }

              renderDiffPreview(refined.diff || `--- original\n+++ proposed\n- ${refined.original_code}\n+ ${refined.proposed_code}`);
              if (elements.fixSplitBefore) elements.fixSplitBefore.textContent = refined.original_code || currentCode;
              if (elements.fixSplitAfter) elements.fixSplitAfter.textContent = refined.proposed_code || refined.proposed_source || "";
            }
          }).catch(err => {
            console.warn("Non-blocking AI refinement notice:", err);
          }).finally(() => {
            if (elements.fixAiRefiningBar) {
              elements.fixAiRefiningBar.style.display = "none";
            }
          });
        }
      } else {
        elements.fixModalExplanation.textContent = `Unable to compute safe fix: ${res.error || 'No matching safe correction rule'}`;
        elements.fixDiffPreview.textContent = "// No automated patch available.";
      }
    } catch (err) {
      elements.fixModalExplanation.textContent = `Error generating fix: ${err.message}`;
      elements.fixDiffPreview.textContent = "// Remediation error.";
    }
  }

  function renderDiffPreview(diffText) {
    if (!elements.fixDiffPreview) return;
    const lines = diffText.split("\n");
    let html = "";
    lines.forEach(l => {
      const escaped = escapeHtml(l);
      if (l.startsWith("+") && !l.startsWith("+++")) {
        html += `<span class="diff-add">${escaped}</span>\n`;
      } else if (l.startsWith("-") && !l.startsWith("---")) {
        html += `<span class="diff-del">${escaped}</span>\n`;
      } else if (l.startsWith("@")) {
        html += `<span class="diff-info">${escaped}</span>\n`;
      } else {
        html += `${escaped}\n`;
      }
    });
    elements.fixDiffPreview.innerHTML = html;
  }

  function closeFixModal() {
    if (elements.fixModalOverlay) {
      elements.fixModalOverlay.style.display = "none";
    }
    if (elements.fixModalCard) {
      elements.fixModalCard.classList.remove("fix-all-mode");
    }
    if (elements.fixModalPerErrorContainer) {
      elements.fixModalPerErrorContainer.style.display = "none";
      elements.fixModalPerErrorContainer.innerHTML = "";
    }
    const viewModes = document.querySelector(".diff-view-modes");
    if (viewModes) viewModes.style.display = "";
    if (elements.fixModalExplanation) elements.fixModalExplanation.style.display = "";
    const diffContainerUnified = document.getElementById("diff-container-unified");
    if (diffContainerUnified) diffContainerUnified.style.display = "";
    if (elements.btnApplyFix) {
      elements.btnApplyFix.textContent = "Apply Remediation to Working Buffer";
    }
    state.security.pendingFix = null;
  }

  function showRepairVerificationNotification(verif) {
    let card = document.getElementById("repair-verification-card");
    const container = document.getElementById("security-findings-container");
    if (!card && container) {
      card = document.createElement("div");
      card.id = "repair-verification-card";
      card.className = "repair-verification-card";
      container.insertBefore(card, container.firstChild);
    }
    if (!card) return;

    const status = verif.status || "passed";
    const statusClass = status === "passed" ? "passed" : (status === "partial" ? "partial" : "failed");
    card.innerHTML = `
      <div class="repair-verif-left">
        <span class="repair-verif-badge repair-verif-${statusClass}">REPAIR ${status.toUpperCase()}</span>
        <span class="repair-verif-text">
          Original findings resolved: <strong>${(verif.resolved_findings || []).length}</strong> • 
          Remaining findings: <strong>${(verif.remaining_findings || []).length}</strong> • 
          Updated Risk Score: <strong>${verif.updated_risk_score}/100</strong>
        </span>
      </div>
      <button class="btn btn-secondary btn-sm" id="btn-dismiss-verif" style="font-size: 11px; padding: 2px 6px;">✕</button>
    `;
    card.style.display = "flex";
    const dismissBtn = document.getElementById("btn-dismiss-verif");
    if (dismissBtn) {
      dismissBtn.addEventListener("click", () => {
        card.style.display = "none";
      });
    }
  }

  async function applyReviewedFix() {
    if (state.security.pendingFix && state.security.pendingFix.is_initial_view) {
      if (elements.btnApplyFix) {
        elements.btnApplyFix.disabled = true;
        elements.btnApplyFix.innerHTML = '<span class="spinner-sm"></span> Applying fixes...';
      }

      try {
        const currentCode = state.editor.getValue();
        const resp = await sourceRequest("/api/ai/fix-all-stages", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            source_code: currentCode,
            language: state.currentFile ? state.currentFile.language : "English",
            file_path: state.currentFile ? state.currentFile.path : "",
            use_ai: elements.toggleStage12Ai ? elements.toggleStage12Ai.checked : false
          })
        });

        const data = await resp.json();
        if (!data.success) {
          setStatus("Fix All Stages could not generate automated repairs: " + (data.error || "Unknown error"), "warning");
          if (elements.btnApplyFix) {
            elements.btnApplyFix.disabled = false;
            elements.btnApplyFix.textContent = "Retry";
          }
          return;
        }

        openFixAllModal("all", data, data.applied_fixes || []);
      } catch (err) {
        console.error("Fix All execution error:", err);
        if (elements.btnApplyFix) {
          elements.btnApplyFix.disabled = false;
          elements.btnApplyFix.textContent = "Retry";
        }
      }
      return;
    }

    if (elements.btnApplyFix && elements.btnApplyFix.textContent.includes("Retry")) {
      const p = state.security.pendingFix || {};
      closeFixModal();
      if (p.is_fix_all) {
        handleFixAllClick(p.stage_id);
      } else if (p.target_finding_id) {
        openFixModal(p.target_finding_id, { id: p.target_finding_id });
      }
      return;
    }

    if (!state.security.pendingFix || !state.security.pendingFix.proposed_source) {
      closeFixModal();
      return;
    }

    const currentCode = state.editor.getValue();
    const proposedCode = state.security.pendingFix.proposed_source;
    const pending = state.security.pendingFix;

    // Validate proposal freshness and identity
    if (proposedCode === currentCode) {
      setStatus("Status: Already applied.", "ready");
      closeFixModal();
      runCompiler(null, true);
      return;
    }
    if (pending.revision_id !== await revisionOf(currentCode) || (pending.source_revision && pending.source_revision !== state.sourceRevisionId)) {
      setStatus("Source changed since this fix was suggested, regenerating...", "running");
      closeFixModal();
      if (pending.is_fix_all) {
        handleFixAllClick(pending.stage_id);
      } else if (pending.target_finding_id) {
        openFixModal(pending.target_finding_id, { id: pending.target_finding_id });
      }
      return;
    }
    if (pending.file_path && state.currentFile && pending.file_path !== state.currentFile.path) {
      setStatus("This fix belongs to a different file. Please re-generate the fix for the active file.", "warning");
      closeFixModal();
      return;
    }

    // Disable button to prevent duplicate clicks while patch is in flight
    if (elements.btnApplyFix) {
      elements.btnApplyFix.disabled = true;
      elements.btnApplyFix.textContent = "Applying & Verifying...";
    }

    try {
      setStatus("Applying and verifying correction against compiler pipeline...", "running");

      // 1. Post to backend /api/ai/apply-fix for atomic verification and persistence
      const applyResp = await sourceRequest("/api/ai/apply-fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          file_path: (state.currentFile && state.currentFile.path) || pending.file_path || "",
          code: proposedCode, preview_revision: pending.revision_id, proposed_hash: pending.proposed_hash,
          source_revision: state.sourceRevisionId,
          stage_id: pending.stage_id || "syntax_analysis",
          language: (state.currentFile && state.currentFile.language) || "English",
          finding_id: pending.target_finding_id || ""
        })
      });

      const applyData = await applyResp.json();
      if (applyData.status === "already_applied") {
        setStatus("Status: Already applied.", "ready");
        closeFixModal();
        await runCompiler(null, true);
        return;
      }
      if (applyData.status === "stale_revision" || (!applyData.success && applyData.error && applyData.error.includes("Source changed since this fix was suggested"))) {
        setStatus("Source changed since this fix was suggested, regenerating...", "running");
        closeFixModal();
        if (pending.is_fix_all) {
          handleFixAllClick(pending.stage_id);
        } else if (pending.target_finding_id) {
          openFixModal(pending.target_finding_id, { id: pending.target_finding_id });
        }
        return;
      }
      if (!applyResp.ok || !applyData.success) {
        if (elements.btnApplyFix) {
          elements.btnApplyFix.disabled = false;
          elements.btnApplyFix.textContent = "Retry with AI";
        }
        const resultsPanel = document.getElementById("fix-modal-results-panel");
        const errText = applyData.error || "Validation failed.";
        if (resultsPanel) {
          resultsPanel.innerHTML = `
            <div class="fix-result-item error-banner" style="background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #fecaca; padding: 12px; border-radius: 6px; margin-bottom: 10px;">
              <strong>✕ Patch Application Rejected:</strong> ${escapeHtml(errText)}<br>
              <div style="margin-top: 4px;"><em>What to do:</em> The patch introduced compiler or security regressions. You can retry with AI or adjust the proposed patch.</div>
            </div>
          ` + resultsPanel.innerHTML;
          resultsPanel.style.display = "flex";
        }
        setStatus("Patch Rejected: " + errText, "error");
        return;
      }

      // 2. Snapshot working buffer for undo
      state.security.undoStack.push({
        code: currentCode,
        timestamp: Date.now(),
        label: pending.is_fix_all ? `Pre-Fix-All for ${pending.stage_id}` : `Pre-fix for ${pending.target_finding_id || ''}`,
        findingsStore: JSON.parse(JSON.stringify(state.findingsStore || {}))
      });
      updateUndoButtonsState();

      // 3. Update editor buffer and source revision
      state.sourceRevisionId = applyData.source_revision || (state.sourceRevisionId + 1);
      state.issuesCache = {};
      state.editor.setValue(proposedCode);
      updateUndoButtonsState(true);
      saveCurrentFileBuffer();

      // Requirement 1 & 5: Clear pipeline state, update orange dot, update save button, recompute health
      resetPipelineFullState("apply_fix");
      updateTabModifiedIndicator();
      updateSaveButtonState();
      await runHealthAnalysis(true);

      // Check suspect fix warning (Requirement 3)
      if (applyData.is_suspect || applyData.suspect || pending.is_suspect) {
        const warnMsg = applyData.suspect_warning || (pending.suspect_warnings && pending.suspect_warnings.join("\n")) || "A flagged line was deleted or replaced rather than remediated.";
        setStatus("WARNING: Suspect Fix Applied — " + warnMsg, "warning");
      }

      // Delta display in Code Health panel (Requirement 2)
      const deltaStr = pending.delta_text || applyData.delta_text;
      if (deltaStr) {
        if (elements.healthFixDeltaText) elements.healthFixDeltaText.textContent = deltaStr;
        if (elements.healthFixDelta) elements.healthFixDelta.style.display = "inline-flex";
      }

      // 4. Update findings store
      if (pending.target_finding_id && state.findingsStore[pending.target_finding_id]) {
        state.findingsStore[pending.target_finding_id].status = "resolved";
        state.findingsStore[pending.target_finding_id].validation_status = "validated_resolved";
        delete state.findingFixes[pending.target_finding_id];
      }
      if (pending.fixes && Array.isArray(pending.fixes)) {
        pending.fixes.forEach(f => {
          const fid = f.finding_id || f.rule_id;
          if (fid && state.findingsStore[fid]) {
            state.findingsStore[fid].status = "resolved";
            state.findingsStore[fid].validation_status = "validated_resolved";
          }
        });
      }

      closeFixModal();

      // 5. Invalidate ALL stages to STALE since source revision changed
      invalidateAllStagesForNewRevision(state.sourceRevisionId);

      setStatus(`Status: Applied Revision ${state.sourceRevisionId}. Re-verifying stage security & pipeline...`, "running");

      // 6. Automatically restart compilation from start to revalidate all 14 stages
      await runCompiler(null, true);

    } catch (err) {
      console.error("Apply fix error:", err);
      setStatus("Unexpected error applying fix: " + err.message, "error");
    } finally {
      if (elements.btnApplyFix) {
        elements.btnApplyFix.disabled = false;
        elements.btnApplyFix.textContent = "Approve & Apply";
      }
    }
  }

  async function undoLastSecurityFix() {
    if (!state.currentFile || !state.currentFile.path) return;
    const path = state.currentFile.path;

    try {
      const resp = await fetch("/api/working-source/undo", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: path })
      });
      const data = await resp.json();
      if (data.success) {
        const reverted = data.working_source;
        state.issuesCache = {};
        state.editor.setValue(reverted);
        state.sourceRevisionId = data.source_revision;
        state.contentHash = data.content_hash;
        if (state.pipeline) {
          state.pipeline.sourceRevisionId = state.sourceRevisionId;
          state.pipeline.compiledSource = null;
          state.pipeline.isReportGenerated = false;
          state.pipeline.isReadyForReport = false;
        }
        if (state.fileStore[path]) {
          state.fileStore[path].workingBuffer = reverted;
          state.fileStore[path].isDirty = Boolean(data.is_modified);
          state.fileStore[path].source_revision = data.source_revision;
          state.fileStore[path].content_hash = data.content_hash;
          persistWorkingBuffersToStorage();
        }
        if (data.is_modified) {
          elements.tabDirtyIndicator.classList.add("visible");
        } else {
          elements.tabDirtyIndicator.classList.remove("visible");
        }
        updateUndoButtonsState(Boolean(data.can_undo));
        setStatus(`Status: Reverted to previous snapshot (${data.restored_label || 'Undo'})`, "ready");
        resetPipelineFullState("undo_fix");
        updateTabModifiedIndicator();
        updateSaveButtonState();
        runHealthAnalysis(true);
        if (state.pipeline.activeDrawerStage) {
          renderStageDrawer(state.pipeline.activeDrawerStage);
        }
        return;
      }
    } catch (e) {
      console.warn("Backend undo error, trying local memory fallback:", e);
    }

    // Fallback to local memory undo stack if backend had no snapshots
    if (state.security.undoStack && state.security.undoStack.length > 0) {
      const lastState = state.security.undoStack.pop();
      if (lastState && typeof lastState.code === "string") {
        state.editor.setValue(lastState.code);
        if (lastState.findingsStore) {
          state.findingsStore = lastState.findingsStore;
        }
        saveCurrentFileBuffer();
        updateUndoButtonsState();
        setStatus("Status: Reverted editor to previous working buffer snapshot (Undo)", "ready");
        resetPipelineFullState("undo_fix");
        updateTabModifiedIndicator();
        updateSaveButtonState();
        runHealthAnalysis(true);
        if (state.pipeline.activeDrawerStage) {
          renderStageDrawer(state.pipeline.activeDrawerStage);
        }
      }
    }
  }

  function bindSecurityEvents() {
    if (elements.tabBtnSecurity) {
      elements.tabBtnSecurity.addEventListener("click", () => {
        switchOutputTab("tab-out-security");
      });
    }

    if (elements.btnScanSecurity) {
      elements.btnScanSecurity.addEventListener("click", () => {
        runSecurityScan(true);
      });
    }

    if (elements.btnUndoFix) {
      elements.btnUndoFix.addEventListener("click", undoLastSecurityFix);
    }

    if (elements.btnCloseFixModal) {
      elements.btnCloseFixModal.addEventListener("click", closeFixModal);
    }

    if (elements.btnRejectFix) {
      elements.btnRejectFix.addEventListener("click", closeFixModal);
    }

    if (elements.btnApplyFix) {
      elements.btnApplyFix.addEventListener("click", applyReviewedFix);
    }
  }

  /* ========================================================================
     CODE HEALTH INDICATOR & PANEL
     ======================================================================== */
  let healthAbortController = null;
  let healthDebounceTimer = null;

  function scheduleHealthAnalysis(delayMs = 600, markStale = true) {
    if (state.isExecuting) return; // Do not recompute while compiler is executing
    if (markStale) {
      updateHealthChipStale();
    }
    if (healthDebounceTimer) {
      clearTimeout(healthDebounceTimer);
    }
    healthDebounceTimer = setTimeout(() => {
      runHealthAnalysis();
    }, delayMs);
  }

  function updateHealthChipAnalysing() {
    const chip = elements.editorHealthChip;
    if (!chip) return;
    chip.className = "health-chip status-analysing";
    chip.setAttribute("title", "Code Health: Analysing editor buffer...");
    chip.setAttribute("aria-label", "Code Health: Analysing editor buffer");
    const summary = document.getElementById("health-chip-details");
    if (summary) summary.textContent = "Analysing...";
  }

  function updateHealthChipStale() {
    const chip = elements.editorHealthChip;
    if (!chip) return;
    chip.className = "health-chip status-stale";
    chip.setAttribute("title", "Code Health: Modified buffer. Analysis pending...");
    chip.setAttribute("aria-label", "Code Health: Modified buffer, analysis pending");
    const summary = document.getElementById("health-chip-details");
    if (summary) summary.textContent = "Stale ↻";
  }

  function renderHealthChip(data) {
    const chip = elements.editorHealthChip;
    if (!chip || !data) return;

    const status = (data.status || "healthy").toLowerCase();
    const score = typeof data.score === "number" ? data.score : 0;
    const grade = data.grade || "-";
    const errorCount = (data.errors && data.errors.length) || 0;
    const insecurePct = data.security && typeof data.security.insecure_percentage === "number" ? data.security.insecure_percentage : 0;
    const deadCodePct = data.dead_code && typeof data.dead_code.percentage === "number" ? data.dead_code.percentage : 0;

    // Class by status: healthy (green), warnings (amber), errors (red), unsafe (red/rose)
    chip.className = `health-chip status-${status}`;

    // Compact summary label according to spec: [ ● 72 B · ⚠ 3 err · 18% unsafe ]
    let detailsText = `${score} ${grade}`;
    if (errorCount > 0) {
      detailsText += ` · ⚠ ${errorCount} err`;
    }
    if (insecurePct > 0) {
      detailsText += ` · ${insecurePct}% unsafe`;
    } else if (errorCount === 0 && status === "healthy") {
      detailsText += ` · 0 err`;
    }

    const summary = document.getElementById("health-chip-details");
    if (summary) summary.textContent = detailsText;

    // Tooltip according to spec: score, grade, errors, dead-code %, insecure %, breakdown
    const bSummary = data.breakdown && data.breakdown.summary ? `\nBreakdown: ${data.breakdown.summary}` : "";
    const tooltip = `Health: ${score}/100 (Grade ${grade}, ${status})${bSummary}\nErrors: ${errorCount} | Dead Code: ${deadCodePct}% | Insecure: ${insecurePct}%\nClick to open Code Health panel.`;
    chip.setAttribute("title", tooltip);
    chip.setAttribute("aria-label", `Code Health: ${score} out of 100, Grade ${grade}, ${status}. Click to open Code Health panel.`);

    // Requirement 3: If health status is errors, change the Run button label tooltip to "Compilation is expected to fail at Stage N" but keep it enabled.
    if (elements.btnRun) {
      if (status === "errors" && data.blocking_stage) {
        elements.btnRun.setAttribute("title", `Compilation is expected to fail at Stage ${data.blocking_stage.stage} (${data.blocking_stage.name})`);
      } else {
        elements.btnRun.setAttribute("title", "Execute Pipeline (Ctrl + Enter)");
      }
      elements.btnRun.disabled = false;
    }
  }

  function renderPreflightStrip(healthData) {
    if (!elements.pipelinePreflightStrip || !healthData) return;
    const blockingStage = healthData.blocking_stage;
    const errors = healthData.errors || [];
    const errCount = errors.length;
    const firstErr = errCount > 0 ? errors[0] : null;
    const secFindings = (healthData.security && healthData.security.findings) || [];
    const secCount = secFindings.length;
    const highCount = secFindings.filter(f => ["CRITICAL", "HIGH"].includes((f.severity || "").toUpperCase())).length;

    let preflightText = "Preflight: ";
    if (blockingStage) {
      let errKind = "compiler error";
      if (firstErr && firstErr.code) {
        if (firstErr.code.startsWith("SYN")) errKind = "syntax error";
        else if (firstErr.code.startsWith("SEM")) errKind = "semantic error";
        else if (firstErr.code.startsWith("LEX")) errKind = "lexical error";
      }
      const linePart = firstErr && firstErr.line ? ` (line ${firstErr.line})` : "";
      preflightText += `predicted stop at Stage ${blockingStage.stage} — ${errCount} ${errKind}${errCount > 1 ? "s" : ""}${linePart}. `;
    } else {
      preflightText += "predicted to pass Stages 1–10. ";
    }
    preflightText += `Security: ${secCount} finding${secCount !== 1 ? "s" : ""}${secCount > 0 ? ` (${highCount} high)` : ""}.`;

    if (elements.pipelinePreflightMessage) {
      elements.pipelinePreflightMessage.textContent = preflightText;
    }
    if (elements.pipelinePreflightAccuracy) {
      elements.pipelinePreflightAccuracy.style.display = "none";
    }
    elements.pipelinePreflightStrip.style.display = "flex";
  }

  function evaluatePredictionAccuracy(status, artifacts) {
    if (!state.activePreflightHealth) return;

    const health = state.activePreflightHealth;
    const blocking = health.blocking_stage;
    const predictedStage = (blocking && typeof blocking.stage === "number") ? blocking.stage : null;

    const normStatus = String(status || "").toLowerCase();
    let actualStage = null;

    if (artifacts) {
      if (typeof artifacts.blocking_stage_num === "number") {
        actualStage = artifacts.blocking_stage_num;
      } else if (artifacts.blocking_stage_id && STAGE_INFO_NUM[artifacts.blocking_stage_id]) {
        actualStage = STAGE_INFO_NUM[artifacts.blocking_stage_id];
      } else if (artifacts.failed_stage && STAGE_INFO_NUM[artifacts.failed_stage]) {
        actualStage = STAGE_INFO_NUM[artifacts.failed_stage];
      }
    }

    if (!actualStage && (normStatus === "completed" || normStatus === "warning" || normStatus === "executed_with_override")) {
      actualStage = null;
    } else if (!actualStage && normStatus === "blocked_by_security") {
      actualStage = 11;
    }

    const isPassPredicted = (predictedStage === null);
    const isPassActual = (actualStage === null || actualStage > 10);
    const isMatch = (isPassPredicted && isPassActual) || (!isPassPredicted && predictedStage === actualStage);

    if (elements.pipelinePreflightStrip) {
      elements.pipelinePreflightStrip.style.display = "flex";
    }

    if (isMatch) {
      if (elements.pipelinePreflightAccuracy) {
        elements.pipelinePreflightAccuracy.textContent = "Prediction matched ✓";
        elements.pipelinePreflightAccuracy.className = "preflight-accuracy-tag match";
        elements.pipelinePreflightAccuracy.style.display = "inline-flex";
      }
      if (elements.healthAccuracyBadge) {
        elements.healthAccuracyBadge.textContent = "Prediction matched ✓";
        elements.healthAccuracyBadge.className = "health-accuracy-badge accuracy-match";
        elements.healthAccuracyBadge.style.display = "inline-flex";
      }
    } else {
      if (elements.pipelinePreflightAccuracy) {
        elements.pipelinePreflightAccuracy.textContent = "Prediction mismatch ✗";
        elements.pipelinePreflightAccuracy.className = "preflight-accuracy-tag mismatch";
        elements.pipelinePreflightAccuracy.style.display = "inline-flex";
      }
      if (elements.healthAccuracyBadge) {
        elements.healthAccuracyBadge.textContent = "Prediction mismatch ✗";
        elements.healthAccuracyBadge.className = "health-accuracy-badge accuracy-mismatch";
        elements.healthAccuracyBadge.style.display = "inline-flex";
      }

      const predLabel = predictedStage !== null ? predictedStage : "Pass";
      const actLabel = actualStage !== null ? actualStage : "Pass";
      const mismatchWarn = `[health] prediction mismatch: predicted Stage ${predLabel}, actual Stage ${actLabel}`;
      console.warn(mismatchWarn);

      const mismatchNote = `\n\n[PREFLIGHT PREDICTION MISMATCH]\n${mismatchWarn}\n`;
      if (elements.consolePipeline) {
        elements.consolePipeline.textContent += mismatchNote;
      }
      if (artifacts) {
        if (typeof artifacts.aggregated_log === "string") {
          artifacts.aggregated_log += mismatchNote;
        }
        if (typeof artifacts.diagnostic_report === "string") {
          artifacts.diagnostic_report += mismatchNote;
        }
      }
    }
  }

  function renderHealthPanel(data) {
    if (!data) return;

    // 1. Header Ring, Grade, Status, Metadata
    const score = typeof data.score === "number" ? data.score : 0;
    const grade = data.grade || "-";
    const status = (data.status || "healthy").toLowerCase();

    const scoreNumEl = document.getElementById("health-score-number");
    const gradeLetterEl = document.getElementById("health-grade-letter");
    const ringCircle = document.getElementById("health-ring-circle");
    const statusBadge = document.getElementById("health-status-text");
    const analyzedTimeEl = document.getElementById("health-analyzed-time");
    const hashShortEl = document.getElementById("health-hash-short");
    const summaryLineEl = document.getElementById("health-summary-line");

    if (scoreNumEl) scoreNumEl.textContent = score;
    if (gradeLetterEl) gradeLetterEl.textContent = `GRADE ${grade}`;

    // Circumference for r=34 is 2 * PI * 34 = 213.628
    if (ringCircle) {
      const circum = 213.6;
      const offset = circum - (score / 100) * circum;
      ringCircle.style.strokeDashoffset = `${offset}`;
      if (status === "healthy") {
        ringCircle.style.stroke = "#16a34a";
      } else if (status === "warnings") {
        ringCircle.style.stroke = "#d97706";
      } else {
        ringCircle.style.stroke = "#dc2626";
      }
    }

    if (statusBadge) {
      statusBadge.textContent = status.toUpperCase();
      statusBadge.className = `health-status-badge status-${status}`;
    }

    if (analyzedTimeEl && data.analyzed_at) {
      try {
        const d = new Date(data.analyzed_at);
        analyzedTimeEl.textContent = d.toLocaleTimeString();
      } catch (e) {
        analyzedTimeEl.textContent = data.analyzed_at.slice(11, 19) || "--:--:--";
      }
    }

    if (hashShortEl && data.source_hash) {
      hashShortEl.textContent = data.source_hash.slice(0, 8);
    }

    if (summaryLineEl) {
      if (status === "healthy") {
        summaryLineEl.textContent = "All static health heuristics passed. Ready for execution.";
      } else if (status === "warnings") {
        summaryLineEl.textContent = "Non-blocking diagnostics detected. Review before running.";
      } else if (status === "errors") {
        const errCount = (data.errors && data.errors.length) || 0;
        summaryLineEl.textContent = `${errCount} compiler error(s) will block build at Stage ${data.blocking_stage ? data.blocking_stage.stage : 1}.`;
      } else {
        summaryLineEl.textContent = "Security risks detected. Pre-run check suggests gating.";
      }
    }

    // 2. Horizontal Stacked Bars
    const insecurePct = data.security && typeof data.security.insecure_percentage === "number" ? data.security.insecure_percentage : 0;
    const deadCodePct = data.dead_code && typeof data.dead_code.percentage === "number" ? data.dead_code.percentage : 0;
    const codeLines = (data.metrics && data.metrics.code_lines) || 1;
    const errCount = (data.errors && data.errors.length) || 0;
    const errorDensity = Math.round((errCount / Math.max(1, codeLines)) * 1000) / 10;

    const bSummary = data.breakdown && data.breakdown.summary ? data.breakdown.summary : "";
    const valInsecure = document.getElementById("health-val-insecure");
    const fillInsecure = document.getElementById("health-fill-insecure");
    if (valInsecure) {
      valInsecure.textContent = `${insecurePct}%`;
      if (bSummary) valInsecure.title = `Breakdown: ${bSummary}`;
    }
    if (fillInsecure) fillInsecure.style.width = `${Math.min(100, insecurePct)}%`;

    const valDeadcode = document.getElementById("health-val-deadcode");
    const fillDeadcode = document.getElementById("health-fill-deadcode");
    if (valDeadcode) {
      valDeadcode.textContent = `${deadCodePct}%`;
      if (bSummary) valDeadcode.title = `Breakdown: ${bSummary}`;
    }
    if (fillDeadcode) fillDeadcode.style.width = `${Math.min(100, deadCodePct)}%`;

    const valDensity = document.getElementById("health-val-density");
    const fillDensity = document.getElementById("health-fill-density");
    if (valDensity) valDensity.textContent = `${errorDensity} / 100 lines`;
    if (fillDensity) fillDensity.style.width = `${Math.min(100, errorDensity * 10)}%`;

    // 3. Mini Predicted Pipeline
    const miniPipelineEl = document.getElementById("health-mini-pipeline");
    const stageNames = ["Src", "Lex", "Par", "AST", "Sem", "Sym", "IR", "Opt", "Gen", "Val"];
    if (miniPipelineEl) {
      miniPipelineEl.innerHTML = "";
      const pred = data.predicted_pipeline || [];
      for (let i = 1; i <= 10; i++) {
        const stageInfo = pred.find(p => p.stage === i) || { status: "not_reached" };
        const node = document.createElement("div");
        node.className = `health-mini-node ${stageInfo.status}`;
        node.title = `Stage ${i} (${stageNames[i - 1]}): ${stageInfo.status}`;
        let icon = stageInfo.status === "pass" ? "✓" : (stageInfo.status === "fail" ? "✗" : "·");
        node.textContent = `${i}:${icon}`;
        miniPipelineEl.appendChild(node);
      }
    }

    const verdictEl = document.getElementById("health-prediction-verdict");
    const verdictIcon = document.getElementById("health-verdict-icon");
    const verdictText = document.getElementById("health-verdict-text");
    if (verdictEl && verdictText) {
      if (data.blocking_stage) {
        verdictEl.className = "health-prediction-verdict verdict-fail";
        if (verdictIcon) verdictIcon.textContent = "⛔";
        verdictText.textContent = `Will stop at Stage ${data.blocking_stage.stage} (${data.blocking_stage.name}): ${data.blocking_stage.reason}`;
      } else {
        verdictEl.className = "health-prediction-verdict verdict-pass";
        if (verdictIcon) verdictIcon.textContent = "✅";
        verdictText.textContent = "Predicted to pass Stages 1–10. Run compiler to confirm live execution.";
      }
    }

    // 4. Collapsible Diagnostic Sections
    // Errors
    const errorsList = document.getElementById("health-list-errors");
    const countErrors = document.getElementById("health-count-errors");
    const errs = data.errors || [];
    if (countErrors) countErrors.textContent = errs.length;
    if (errorsList) {
      errorsList.innerHTML = "";
      if (errs.length === 0) {
        errorsList.innerHTML = '<div class="health-empty-msg">No syntax, lexical, or semantic errors found.</div>';
      } else {
        errs.forEach(err => {
          const row = document.createElement("div");
          row.className = "health-item-row";
          row.setAttribute("role", "button");
          row.setAttribute("tabindex", "0");
          row.title = `Click to scroll to Line ${err.line}, Column ${err.column || 1}`;
          row.innerHTML = `
            <div class="health-item-top">
              <div class="health-item-badges">
                <span class="health-code-badge badge-danger">${err.code}</span>
                <span class="health-code-badge">Stage ${err.stage}</span>
              </div>
              <span class="health-item-loc">Ln ${err.line}:${err.column || 1}</span>
            </div>
            <div class="health-item-msg">${escapeHtml(err.message)}</div>
          `;
          row.addEventListener("click", () => jumpToEditorLine(err.line, err.column || 1));
          row.addEventListener("keydown", (e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              jumpToEditorLine(err.line, err.column || 1);
            }
          });
          errorsList.appendChild(row);
        });
      }
    }

    // Dead Code
    const deadList = document.getElementById("health-list-deadcode");
    const countDead = document.getElementById("health-count-deadcode");
    const deadItems = (data.dead_code && data.dead_code.items) || [];
    if (countDead) countDead.textContent = deadItems.length;
    if (deadList) {
      deadList.innerHTML = "";
      if (deadItems.length === 0) {
        deadList.innerHTML = '<div class="health-empty-msg">No dead code or unused identifiers detected.</div>';
      } else {
        deadItems.forEach(item => {
          const row = document.createElement("div");
          row.className = "health-item-row";
          row.setAttribute("role", "button");
          row.setAttribute("tabindex", "0");
          row.title = `Click to scroll to Line ${item.line}`;
          row.innerHTML = `
            <div class="health-item-top">
              <div class="health-item-badges">
                <span class="health-code-badge">${item.kind}</span>
                ${item.name ? `<span class="health-code-badge"><code>${escapeHtml(item.name)}</code></span>` : ""}
              </div>
              <span class="health-item-loc">Ln ${item.line}</span>
            </div>
            <div class="health-item-msg">${escapeHtml(item.message)}</div>
          `;
          row.addEventListener("click", () => jumpToEditorLine(item.line));
          row.addEventListener("keydown", (e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              jumpToEditorLine(item.line);
            }
          });
          deadList.appendChild(row);
        });
      }
    }

    // Security Findings
    const secList = document.getElementById("health-list-security");
    const countSec = document.getElementById("health-count-security");
    const secFindings = (data.security && data.security.findings) || [];
    if (countSec) countSec.textContent = secFindings.length;
    if (secList) {
      secList.innerHTML = "";
      if (secFindings.length === 0) {
        secList.innerHTML = '<div class="health-empty-msg">No deterministic security vulnerabilities detected.</div>';
      } else {
        secFindings.forEach(f => {
          const row = document.createElement("div");
          row.className = "health-item-row";
          row.setAttribute("role", "button");
          row.setAttribute("tabindex", "0");
          row.title = `Click to scroll to Line ${f.line}`;
          const sevLower = (f.severity || "medium").toLowerCase();
          row.innerHTML = `
            <div class="health-item-top">
              <div class="health-item-badges">
                <span class="health-code-badge badge-sev-${sevLower}">${f.severity}</span>
                ${f.cwe ? `<span class="health-code-badge badge-cwe">${f.cwe}</span>` : ""}
                <span class="health-code-badge">${f.id}</span>
              </div>
              <span class="health-item-loc">Ln ${f.line}</span>
            </div>
            <div class="health-item-msg">${escapeHtml(f.message)}</div>
          `;
          row.addEventListener("click", () => jumpToEditorLine(f.line));
          row.addEventListener("keydown", (e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              jumpToEditorLine(f.line);
            }
          });
          secList.appendChild(row);
        });
      }
    }

    // 5. Metrics Grid
    const m = data.metrics || {};
    const totalLinesEl = document.getElementById("metric-total-lines");
    const codeLinesEl = document.getElementById("metric-code-lines");
    const commentLinesEl = document.getElementById("metric-comment-lines");
    const functionsEl = document.getElementById("metric-functions");
    const maxNestingEl = document.getElementById("metric-max-nesting");
    const complexityEl = document.getElementById("metric-complexity");

    if (totalLinesEl) totalLinesEl.textContent = m.total_lines || 0;
    if (codeLinesEl) codeLinesEl.textContent = m.code_lines || 0;
    if (commentLinesEl) commentLinesEl.textContent = m.comment_lines || 0;
    if (functionsEl) functionsEl.textContent = m.functions || 0;
    if (maxNestingEl) maxNestingEl.textContent = m.max_nesting_depth || 0;
    if (complexityEl) {
      complexityEl.textContent = `${m.cyclomatic_complexity_total || 0} / ${m.cyclomatic_complexity_max || 0}`;
    }

    // Hide error fallback state
    const errState = document.getElementById("health-error-state");
    if (errState) errState.style.display = "none";

    // Update Fix All Issues button in Health Panel via state machine
    if (elements.btnHealthFixAll) {
      const fixableCount = typeof data.fixable_count === "number" ? data.fixable_count : (
        (data.issues ? data.issues.length : 0)
      );
      if (fixableCount > 0) {
        setFixAllButtonState("ready", fixableCount);
        if (data.breakdown && data.breakdown.summary) {
          elements.btnHealthFixAll.setAttribute("title", `Fix all issues: ${data.breakdown.summary}`);
        }
      } else {
        setFixAllButtonState("none");
      }
    }
  }

  function renderHealthGutterMarkers(data) {
    if (!state.editor) return;
    try {
      state.editor.clearGutter("health-gutter-markers");
    } catch (e) {
      return;
    }

    if (!data) return;

    const lineErrors = new Map();
    (data.errors || []).forEach(e => {
      const l = e.line;
      if (!lineErrors.has(l)) lineErrors.set(l, []);
      lineErrors.get(l).push(e);
    });

    const lineSec = new Map();
    ((data.security && data.security.findings) || []).forEach(f => {
      const l = f.line;
      if (!lineSec.has(l)) lineSec.set(l, []);
      lineSec.get(l).push(f);
    });

    const lineDead = new Map();
    ((data.dead_code && data.dead_code.items) || []).forEach(d => {
      const l = d.line;
      if (!lineDead.has(l)) lineDead.set(l, []);
      lineDead.get(l).push(d);
    });

    const allLines = new Set([...lineErrors.keys(), ...lineSec.keys(), ...lineDead.keys()]);
    const maxLines = state.editor.lineCount();

    allLines.forEach(lineNum => {
      if (lineNum < 1 || lineNum > maxLines) return;
      const lineIdx = lineNum - 1;

      const marker = document.createElement("span");
      marker.className = "health-gutter-dot";

      if (lineErrors.has(lineNum)) {
        marker.classList.add("dot-error");
        marker.title = `Error: ${lineErrors.get(lineNum)[0].message}`;
      } else if (lineSec.has(lineNum)) {
        marker.classList.add("dot-security");
        marker.title = `Security Finding: ${lineSec.get(lineNum)[0].message}`;
      } else if (lineDead.has(lineNum)) {
        marker.classList.add("dot-warning");
        marker.title = `Dead Code: ${lineDead.get(lineNum)[0].message}`;
      }

      marker.addEventListener("click", () => {
        jumpToEditorLine(lineNum);
        switchOutputTab("tab-out-health");
      });

      state.editor.setGutterMarker(lineIdx, "health-gutter-markers", marker);
    });
  }

  function renderHealthErrorState(errorMsg) {
    const chip = elements.editorHealthChip;
    if (chip) {
      chip.className = "health-chip status-stale";
      const summary = document.getElementById("health-chip-details");
      if (summary) summary.textContent = "Unavailable ⚠️";
      chip.setAttribute("title", `Health analysis unavailable: ${errorMsg}`);
    }

    const errState = document.getElementById("health-error-state");
    const errReason = document.getElementById("health-error-reason");
    if (errState) errState.style.display = "flex";
    if (errReason) errReason.textContent = errorMsg || "Could not connect to health analyzer.";
  }

  function jumpToEditorLine(line, col = 1) {
    if (!state.editor || line < 1) return;
    const lineIdx = line - 1;
    const colIdx = Math.max(0, col - 1);
    state.editor.setCursor({ line: lineIdx, ch: colIdx });
    state.editor.scrollIntoView({ line: lineIdx, ch: colIdx }, 80);
    state.editor.focus();

    const lineHandle = state.editor.addLineClass(lineIdx, "background", "health-line-highlight");
    setTimeout(() => {
      try {
        state.editor.removeLineClass(lineHandle, "background", "health-line-highlight");
      } catch (e) { }
    }, 2500);
  }

  async function runHealthAnalysis(force = false) {
    if (state.isExecuting) return; // Do not recompute while running
    if (!state.editor) return;

    const source = state.editor.getValue();
    const lang = (state.currentFile && state.currentFile.language) || "English";
    const filename = (state.currentFile && state.currentFile.filename) || "source.vital";
    const currentHash = sha256Sync(source);

    if (healthAbortController) {
      healthAbortController.abort();
    }
    healthAbortController = new AbortController();

    updateHealthChipAnalysing();
    setFixAllButtonState("loading");

    try {
      const resp = await fetch("/api/health/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source: source,
          language: lang,
          filename: filename
        }),
        signal: healthAbortController.signal
      });

      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}`);
      }

      const data = await resp.json();

      // Guard: Check if the buffer has changed since request started
      const latestBuffer = state.editor.getValue();
      const latestHash = sha256Sync(latestBuffer);
      if (data.source_hash !== latestHash) {
        return;
      }

      if (!state.issuesCache) state.issuesCache = {};
      state.issuesCache[data.source_hash] = data;

      state.codeHealth = data;
      renderHealthChip(data);
      renderHealthPanel(data);
      renderHealthGutterMarkers(data);

      // Requirement 4: Dev console log lines
      const hHash = (data.source_hash || "").slice(0, 8);
      const hErrors = Array.isArray(data.errors) ? data.errors.length : 0;
      const hInsecure = data.insecure_pct !== undefined ? data.insecure_pct : 0;
      const hDead = data.dead_code_pct !== undefined ? data.dead_code_pct : 0;
      console.log(`[health] analysed ${filename} @ ${hHash} score=${data.score} errors=${hErrors} insecure=${hInsecure}% dead=${hDead}%`);

    } catch (err) {
      if (err.name === "AbortError") {
        return; // Superseded by a newer request
      }
      console.warn("Health analysis error:", err);
      renderHealthErrorState(err.message);
      setFixAllButtonState("error", 0, err.message);
    }
  }

  function switchOutputTab(tabId) {
    if (elements.outputTabsBar) elements.outputTabsBar.style.display = "flex";
    if (elements.outputContentArea) elements.outputContentArea.style.display = "block";

    elements.outputTabBtns.forEach(btn => {
      if (btn.getAttribute("data-tab") === tabId) {
        btn.classList.add("active");
      } else {
        btn.classList.remove("active");
      }
    });

    document.querySelectorAll(".output-tab-content").forEach(content => {
      if (content.id === tabId) {
        content.classList.add("active");
      } else {
        content.classList.remove("active");
      }
    });
  }

  function setRunningUI(isRunning) {
    if (isRunning) {
      if (elements.btnRun) elements.btnRun.style.display = "none";
      if (elements.btnCancelRun) {
        elements.btnCancelRun.style.display = "inline-flex";
        elements.btnCancelRun.disabled = false;
        elements.btnCancelRun.innerHTML = '<span>⏹</span> Cancel';
      }
      elements.btnRun.classList.add("running");
      elements.runBtnIcon.textContent = "⏳";
      elements.runBtnText.textContent = "Running...";
    } else {
      if (elements.btnCancelRun) {
        elements.btnCancelRun.style.display = "none";
        elements.btnCancelRun.disabled = false;
        elements.btnCancelRun.innerHTML = '<span>⏹</span> Cancel';
      }
      if (elements.btnRun) elements.btnRun.style.display = "inline-flex";
      elements.btnRun.classList.remove("running");
      elements.runBtnIcon.textContent = "▶";
      elements.runBtnText.textContent = "Run";
    }
  }

  async function cancelActivePipelineRun() {
    if (!state.isExecuting && !state.pipeline.isRunning) {
      return;
    }
    const runId = state.pipeline.activeRunId;
    setStatus("Cancelling pipeline run...", "running");
    if (elements.btnCancelRun) {
      elements.btnCancelRun.disabled = true;
      elements.btnCancelRun.innerHTML = '<span>⏳</span> Cancelling...';
    }
    try {
      await fetch("/api/pipeline/cancel", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          run_id: runId,
          session_id: state.sessionId
        })
      });
    } catch (err) {
      console.warn("Failed to send cancel request:", err);
    }
  }

  async function recoverRunAfterRefresh() {
    let savedRunId = null;
    try {
      if (typeof sessionStorage !== "undefined") {
        savedRunId = sessionStorage.getItem("vital_active_run_id");
      }
    } catch (e) { }

    if (!savedRunId) return;

    try {
      const resp = await fetch(`/api/runs/${encodeURIComponent(savedRunId)}`);
      if (!resp.ok) {
        try { sessionStorage.removeItem("vital_active_run_id"); } catch (e) { }
        return;
      }
      const data = await resp.json();
      if (!data || !data.success) {
        try { sessionStorage.removeItem("vital_active_run_id"); } catch (e) { }
        return;
      }

      // Verify that the editor buffer matches the run's source_hash
      const currentCode = state.editor ? state.editor.getValue() : "";
      const currentHash = sha256Sync(currentCode);
      if (!data.source_hash || data.source_hash !== currentHash) {
        // Buffer has changed since the run was executed, do not rehydrate stale run
        try { sessionStorage.removeItem("vital_active_run_id"); } catch (e) { }
        return;
      }

      // Rehydrate state
      state.pipeline.activeRunId = data.run_id;
      state.pipeline.lastCompletedRunId = data.run_id;
      state.pipeline.compiledSource = currentCode;
      state.pipeline.activeSourceHash = data.source_hash;
      state.currentBufferHash = data.source_hash;
      state.isExecuting = false;
      setRunningUI(false);

      // Rehydrate stages
      if (Array.isArray(data.stages)) {
        for (const stage of data.stages) {
          const sid = stage.id;
          const status = stage.status;
          const evtType = status === "passed" ? "stage_complete" :
            status === "warning" ? "stage_warning" :
              status === "failed" ? "stage_failed" :
                status === "blocked" ? "stage_blocked" :
                  status === "skipped" ? "stage_skipped" :
                    status === "unavailable" ? "stage_unavailable" : "stage_complete";

          handlePipelineEvent({
            event: evtType,
            stage_id: sid,
            run_id: data.run_id,
            source_hash: data.source_hash,
            stage_status: status,
            findings_count: stage.findings_count || (stage.findings ? stage.findings.length : 0),
            summary: stage.summary || stage.reason || "",
            reason: stage.reason || stage.summary || "",
            duration_ms: stage.duration_ms || 0,
            details: { findings: stage.findings || [] }
          });
        }
      }

      // Rehydrate finish / status
      handlePipelineEvent({
        event: "pipeline_finish",
        run_id: data.run_id,
        source_hash: data.source_hash,
        status: data.overall_status || data.status || "completed",
        overall_status: data.overall_status || data.status || "completed",
        header_message: data.header_message || "",
        progress_pct: data.progress_pct,
        completed_count: data.completed_count,
        artifacts: data.artifacts || null
      });

    } catch (err) {
      console.warn("Could not recover run after refresh:", err);
    }
  }

  function setStatus(message, type) {
    elements.statusbarText.textContent = message;
    elements.ideStatusbar.className = "";
    elements.statusIndicatorDot.className = "status-indicator-dot";

    if (type === "running") {
      elements.ideStatusbar.classList.add("status-running");
      elements.statusIndicatorDot.classList.add("running");
    } else if (type === "error") {
      elements.ideStatusbar.classList.add("status-error");
      elements.statusIndicatorDot.classList.add("error");
    }
  }

  /* ========================================================================
     5. FILE ACTIONS (NEW FILE)
     ======================================================================== */
  function getNextUntitledFilename() {
    if (typeof state.untitledCount !== "number") {
      state.untitledCount = 0;
    }
    state.untitledCount++;
    if (state.untitledCount === 1) {
      return "untitled.vital";
    }
    return `untitled-${state.untitledCount}.vital`;
  }

  function createNewFile() {
    saveCurrentFileBuffer();

    const currentLang = (state.currentFile && state.currentFile.language && state.currentFile.language !== "Custom" && state.currentFile.language !== "Uploaded File")
      ? state.currentFile.language
      : "English";

    const filename = getNextUntitledFilename();

    state.currentFile = {
      path: filename,
      filename: filename,
      language: currentLang,
      title: filename,
      originalCode: ""
    };
    state.sourceRevisionId = 1;

    state.editor.setValue("");
    state.editor.clearHistory();
    state.editor.focus();

    updateHeaderAndBreadcrumbs();
    elements.tabDirtyIndicator.classList.remove("visible");

    // Deselect tree active
    document.querySelectorAll(".tree-file-item").forEach(i => i.classList.remove("active"));
    resetPipelineFullState("create_new");
    showOutputWaitingState(
      "Compiler Artifacts Awaiting Completion",
      "Compiler artifacts will appear here after all required stages pass and the Final Report is generated."
    );
    setStatus(`Status: Created new ${filename}`, "ready");
  }

  function exportReportHtml() {
    const reportText = (elements.consolePipeline && elements.consolePipeline.textContent) || "";
    if (!reportText) {
      setStatus("No pipeline report available to export.", "warning");
      return;
    }
    const fileName = (state.currentFile ? state.currentFile.filename : "report") + "_audit.html";
    const htmlDoc = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>VITAL Compiler Execution & Audit Report</title>
  <style>
    body { font-family: monospace; background: #0F172A; color: #E2E8F0; padding: 24px; line-height: 1.5; }
    pre { background: #1E293B; padding: 20px; border-radius: 8px; border: 1px solid #334155; overflow-x: auto; white-space: pre-wrap; font-size: 13px; }
    h1 { color: #38BDF8; font-size: 18px; margin-bottom: 16px; }
  </style>
</head>
<body>
  <h1>VITAL Compiler Pipeline Audit Report</h1>
  <pre>${escapeHtml(reportText)}</pre>
</body>
</html>`;
    const blob = new Blob([htmlDoc], { type: "text/html;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(url);
  }

  function exportReportJson() {
    let artifacts = state.pipeline.pendingArtifacts || {};
    const fileName = (state.currentFile ? state.currentFile.filename : "report") + "_audit.json";
    const isComplete = Boolean(state.pipeline.isFinished && (state.pipeline.finishStatus === "completed" || state.pipeline.finishStatus === "warning") && !artifacts.incomplete);
    if (!isComplete) {
      artifacts = {
        ...artifacts,
        complete: false,
        incomplete: true,
        status: state.pipeline.finishStatus || "incomplete",
        diagnostic_report: elements.consolePipeline ? elements.consolePipeline.textContent : (artifacts.aggregated_log || "")
      };
    }
    const jsonStr = JSON.stringify(artifacts, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(url);
  }

  function copyActiveOutput() {
    const activeTab = document.querySelector(".output-tab-content.active");
    if (!activeTab) return;
    const text = activeTab.innerText;

    navigator.clipboard.writeText(text).then(() => {
      const origText = elements.btnCopyOutput.textContent;
      elements.btnCopyOutput.textContent = "Copied!";
      setTimeout(() => {
        elements.btnCopyOutput.textContent = origText;
      }, 1500);
    });
  }

  /* ========================================================================
     6. PANEL RESIZING DRAG HANDLERS
     ======================================================================== */
  function setupResizers() {
    // Left Explorer resizer
    elements.resizerLeft.addEventListener("mousedown", function (e) {
      e.preventDefault();
      elements.resizerLeft.classList.add("dragging");

      function onMouseMove(moveEvent) {
        const newWidth = Math.max(180, Math.min(500, moveEvent.clientX));
        elements.panelExplorer.style.width = newWidth + "px";
        if (state.editor) state.editor.refresh();
      }

      function onMouseUp() {
        elements.resizerLeft.classList.remove("dragging");
        window.removeEventListener("mousemove", onMouseMove);
        window.removeEventListener("mouseup", onMouseUp);
        if (state.editor) state.editor.refresh();
      }

      window.addEventListener("mousemove", onMouseMove);
      window.addEventListener("mouseup", onMouseUp);
    });

    // Right Output resizer
    elements.resizerRight.addEventListener("mousedown", function (e) {
      e.preventDefault();
      elements.resizerRight.classList.add("dragging");

      function onMouseMove(moveEvent) {
        const windowWidth = window.innerWidth;
        const newWidth = Math.max(260, Math.min(800, windowWidth - moveEvent.clientX));
        elements.panelOutput.style.width = newWidth + "px";
        if (state.editor) state.editor.refresh();
      }

      function onMouseUp() {
        elements.resizerRight.classList.remove("dragging");
        window.removeEventListener("mousemove", onMouseMove);
        window.removeEventListener("mouseup", onMouseUp);
        if (state.editor) state.editor.refresh();
      }

      window.addEventListener("mousemove", onMouseMove);
      window.addEventListener("mouseup", onMouseUp);
    });
  }

  /* ========================================================================
     7. UTILITIES
     ======================================================================== */

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Expose internal API for test harness & diagnostics
  if (typeof window !== "undefined") {
    window.__VITAL_IDE__ = {
      state,
      elements,
      setFixAllButtonState,
      resetPipelineFullState,
      resetPipelineStepper,
      handlePipelineEvent,
      isSecurityResultValidForActiveBuffer,
      sha256Sync,
      setupSecurityBanner,
      loadDemoFile,
      runHealthAnalysis,
      showOutputWaitingState,
      renderSecurityFindings,
      openStageDrawer,
      closeStageDrawer,
      toggleStageDrawer,
      renderStageDrawer,
      recoverRunFinishViaRest,
      computeHeaderStatusFromStages
    };
  }

  // Start IDE when DOM is ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

})();
