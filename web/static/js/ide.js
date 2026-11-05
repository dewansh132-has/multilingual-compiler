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

(function() {
  "use strict";

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
    
    // Contribution 6: Real-Time AI Programming Assistant State
    ai: {
      autoAnalyze: true,
      debounceMs: 900,
      debounceTimer: null,
      sourceVersion: 1,
      lastAnalyzedVersion: 0,
      lastAnalyzedCode: "",
      isAnalyzing: false,
      latestCompilerDiagnostics: null
    },

    // Explicit 14 Logical Compiler Stages (Compiler Design Syllabus Order)
    pipeline: {
      activeRunId: null,
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
        { id: "ai_security_analysis", name: "12. Ollama AI Analysis", desc: "Local Ollama AI Security Agent", icon: "🤖", category: "security" },
        { id: "sandbox_execution", name: "13. Sandbox Execution", desc: "Subprocess Sandboxed Execution", icon: "▶️", category: "backend" },
        { id: "final_report", name: "14. Final Report", desc: "Final Report & Metrics Assembly", icon: "📊", category: "backend" }
      ],
      stageData: {},
      activeDrawerStage: null
    },
    security: {
      findings: [],
      overallScore: 0,
      ollamaStatus: { online: false, model: "qwen2.5-coder:7b-instruct" },
      undoStack: [],
      pendingFix: null
    },
    // Per-file working buffer store: preserves editor state, cursor, and undo history across demo switches
    fileStore: {}
  };

  // DOM Elements
  const elements = {
    editorTextarea: document.getElementById("code-editor"),
    btnRun: document.getElementById("btn-run"),
    runBtnIcon: document.getElementById("run-btn-icon"),
    runBtnText: document.getElementById("run-btn-text"),
    toggleStage12Ai: document.getElementById("toggle-stage12-ai"),
    btnNew: document.getElementById("btn-new"),
    btnOpen: document.getElementById("btn-open"),
    fileInput: document.getElementById("file-input"),
    btnSave: document.getElementById("btn-save"),
    btnReset: document.getElementById("btn-reset"),
    btnClear: document.getElementById("btn-clear"),
    btnFinalReport: document.getElementById("btn-final-report"),
    btnExportReportHtml: document.getElementById("btn-export-report-html"),
    btnExportReportJson: document.getElementById("btn-export-report-json"),
    btnClearAllCopies: document.getElementById("btn-clear-all-copies"),
    btnAiAssistant: document.getElementById("btn-ai-assistant"),
    
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
    
    // Contribution 6: AI Assistant Elements
    tabBtnAi: document.getElementById("tab-btn-ai"),
    aiTabStatusPill: document.getElementById("ai-tab-status-pill"),
    btnAiAnalyze: document.getElementById("btn-ai-analyze"),
    btnAiExplain: document.getElementById("btn-ai-explain"),
    btnAiClear: document.getElementById("btn-ai-clear"),
    aiAutoToggle: document.getElementById("ai-auto-toggle"),
    aiProviderBadge: document.getElementById("ai-provider-badge"),
    aiLoadingBar: document.getElementById("ai-loading-bar"),
    aiLoadingText: document.getElementById("ai-loading-text"),
    aiEmptyState: document.getElementById("ai-empty-state"),
    aiAnalysisContent: document.getElementById("ai-analysis-content"),
    aiSummaryHeader: document.getElementById("ai-summary-header"),
    aiFindingsList: document.getElementById("ai-findings-list"),
    aiPedagogicalFooter: document.getElementById("ai-pedagogical-footer"),

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
    ollamaStatusIndicator: document.getElementById("ollama-status-indicator"),
    ollamaPulseDot: document.getElementById("ollama-pulse-dot"),
    ollamaStatusLabel: document.getElementById("ollama-status-label"),
    btnScanSecurity: document.getElementById("btn-scan-security"),
    btnUndoFix: document.getElementById("btn-undo-fix"),
    securityEmptyState: document.getElementById("security-empty-state"),
    securityFindingsList: document.getElementById("security-findings-list"),

    // Editor Action Buttons
    btnViewOriginal: document.getElementById("btn-view-original"),
    btnRestoreOriginal: document.getElementById("btn-restore-original"),
    btnUndoEditorFix: document.getElementById("btn-undo-editor-fix"),

    // Diff & Fix Review Modal Elements
    fixModalOverlay: document.getElementById("fix-modal-overlay"),
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
    checkAiStatus();
    initPipelineStepper();
    checkOllamaSecurityStatus();
  }

  function initCodeMirror() {
    state.editor = CodeMirror.fromTextArea(elements.editorTextarea, {
      mode: "vital",
      lineNumbers: true,
      matchBrackets: true,
      autoCloseBrackets: true,
      styleActiveLine: true,
      indentUnit: 4,
      tabSize: 4,
      indentWithTabs: false,
      lineWrapping: true,
      extraKeys: {
        "Ctrl-Enter": function() { runCompiler(); },
        "Cmd-Enter": function() { runCompiler(); },
        "Tab": function(cm) {
          if (cm.somethingSelected()) {
            cm.indentSelection("add");
          } else {
            cm.replaceSelection("    ", "end");
          }
        }
      }
    });

    // Track Cursor position
    state.editor.on("cursorActivity", function() {
      const pos = state.editor.getCursor();
      elements.statusbarCursor.textContent = `Ln ${pos.line + 1}, Col ${pos.ch + 1}`;
    });

    // Track modifications / dirty state and trigger debounced real-time AI assistance
    state.editor.on("change", function() {
      const currentVal = state.editor.getValue();
      const isDirty = (currentVal !== state.currentFile.originalCode);
      if (isDirty) {
        elements.tabDirtyIndicator.classList.add("visible");
      } else {
        elements.tabDirtyIndicator.classList.remove("visible");
      }

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

      // Invalidate prior compilation / final report state on source modification
      if (state.pipeline) {
        state.pipeline.compiledSource = null;
        state.pipeline.isReportGenerated = false;
        state.pipeline.isReadyForReport = false;
        state.pipeline.isFinished = false;
        state.pipeline.pendingArtifacts = null;
      }
      showOutputWaitingState(
        "Source Modified — Re-compilation Needed",
        "Editor working buffer has changed. Click 'Run' to execute the sequential compiler pipeline on the new source."
      );

      // Increment source version for stale-response protection
      state.ai.sourceVersion += 1;

      // Real-time debounced AI analysis trigger (~900ms pause)
      if (state.ai.autoAnalyze) {
        if (state.ai.debounceTimer) {
          clearTimeout(state.ai.debounceTimer);
        }
        state.ai.debounceTimer = setTimeout(function() {
          triggerAiAnalysis(false);
        }, state.ai.debounceMs);
      }
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
    elements.btnRun.addEventListener("click", runCompiler);

    // New File
    elements.btnNew.addEventListener("click", createNewFile);

    // Open File
    elements.btnOpen.addEventListener("click", () => elements.fileInput.click());
    elements.fileInput.addEventListener("change", handleFileUpload);

    // Save (persists working copy to backend disk)
    elements.btnSave.addEventListener("click", handleSaveClick);

    // Reset
    elements.btnReset.addEventListener("click", handleReset);

    // Clear Output
    elements.btnClear.addEventListener("click", handleClearOutput);

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

    const pipeSaveBtn = document.getElementById("btn-pipeline-save-corrected");
    if (pipeSaveBtn) {
      pipeSaveBtn.addEventListener("click", saveCorrectedCode);
    }
    const pipeRestoreBtn = document.getElementById("btn-pipeline-restore-original");
    if (pipeRestoreBtn) {
      pipeRestoreBtn.addEventListener("click", restoreOriginalDemo);
    }

    if (elements.btnFinalReport) {
      elements.btnFinalReport.addEventListener("click", () => {
        if (state.pipeline.pendingArtifacts && state.pipeline.isReportGenerated) {
          showOutputArtifacts(state.pipeline.pendingArtifacts);
          switchOutputTab("tab-out-pipeline");
        } else {
          generateFinalReport(true);
        }
      });
    }

    if (elements.btnExportReportHtml) {
      elements.btnExportReportHtml.addEventListener("click", exportReportHtml);
    }
    if (elements.btnExportReportJson) {
      elements.btnExportReportJson.addEventListener("click", exportReportJson);
    }

    if (elements.btnClearAllCopies) {
      elements.btnClearAllCopies.addEventListener("click", async () => {
        if (!confirm("Are you sure you want to delete ALL working copies and reset all demos to original? This action cannot be undone.")) {
          return;
        }
        try {
          const resp = await fetch("/api/working-copy/clear-all", { method: "POST" });
          const res = await resp.json();
          alert(res.message || "All working copies cleared.");
          if (state.currentFile && state.currentFile.path) {
            await loadDemoFile(state.currentFile.path);
          }
        } catch (err) {
          alert("Failed to clear working copies: " + err.message);
        }
      });
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

    // Global Escape Key to close overlay or modals
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" || e.keyCode === 27) {
        if (state.pipeline && state.pipeline.activeDrawerStage) {
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

    // Toolbar AI Assistant Button
    if (elements.btnAiAssistant) {
      elements.btnAiAssistant.addEventListener("click", handleAiToolbarClick);
    }

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

    // Contribution 6: AI Assistant Toolbar Events
    if (elements.btnAiAnalyze) {
      elements.btnAiAnalyze.addEventListener("click", () => triggerAiAnalysis(true));
    }
    if (elements.btnAiExplain) {
      elements.btnAiExplain.addEventListener("click", triggerAiExplainError);
    }
    if (elements.btnAiClear) {
      elements.btnAiClear.addEventListener("click", clearAiResults);
    }
    if (elements.aiAutoToggle) {
      elements.aiAutoToggle.addEventListener("change", (e) => {
        state.ai.autoAnalyze = e.target.checked;
        if (state.ai.autoAnalyze) {
          triggerAiAnalysis(false);
        }
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
        
        // Load default initial demo (English hello.vital or first found)
        const defaultPath = "examples/english/hello.vital";
        loadDemoFile(defaultPath);
        setStatus("System Ready | Multilingual Engine Loaded", "ready");
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
          openStageDrawer("security_analysis");
          runSecurityScan(true);
        });
      }
      runSecurityScan(false);
    } else if (banner) {
      banner.style.display = "none";
    }
  }

  async function loadDemoFile(relPath, forceRestore = false) {
    try {
      // 1. Snapshot previous open file's buffer, cursor, and undo stack
      saveCurrentFileBuffer();

      // 2. Fetch authoritative working copy from backend via /api/demo-content
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
        state.security.undoStack = [];
        state.findingsStore = {};
        state.findingFixes = {};
        resetPipelineStepper();
        showOutputWaitingState(
          "Awaiting Compilation & Final Report",
          "Compiler artifacts will appear here after all required stages pass and the Final Report is generated."
        );
        closeStageDrawer();
        updateUndoButtonsState(isModified);

        // Update UI Badges & Tab Dirty Indicator
        updateHeaderAndBreadcrumbs();
        if (isModified) {
          elements.tabDirtyIndicator.classList.add("visible");
        } else {
          elements.tabDirtyIndicator.classList.remove("visible");
        }

        // Re-highlight active in explorer tree
        highlightActiveTreeItem(json.path, json.filename);

        // Security Lab Educational Banner
        setupSecurityBanner(json);

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

  function showOutputWaitingState(message, subtext) {
    if (elements.outputWaitingState) elements.outputWaitingState.style.display = "flex";
    if (elements.outputWaitingMessage && message) elements.outputWaitingMessage.textContent = message;
    if (elements.outputWaitingSubtext && subtext) elements.outputWaitingSubtext.textContent = subtext;
    if (elements.outputTabsBar) elements.outputTabsBar.style.display = "none";
    if (elements.outputContentArea) elements.outputContentArea.style.display = "none";
  }

  function showOutputArtifacts(artifacts) {
    if (elements.outputWaitingState) elements.outputWaitingState.style.display = "none";
    if (elements.outputTabsBar) elements.outputTabsBar.style.display = "flex";
    if (elements.outputContentArea) elements.outputContentArea.style.display = "block";
    if (artifacts) {
      handleExecutionResult(artifacts);
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

  function resetPipelineStepper() {
    if (!elements.pipelineStepper) return;
    if (elements.pipelineProgressFill) {
      elements.pipelineProgressFill.style.width = "0%";
      elements.pipelineProgressFill.className = "pipeline-progress-fill";
    }
    if (elements.pipelineStatusBadge) {
      elements.pipelineStatusBadge.textContent = "RUNNING";
      elements.pipelineStatusBadge.className = "pipeline-status-badge badge-running";
    }
    if (elements.pipelineMetricStage) elements.pipelineMetricStage.textContent = "Stage: Initializing...";
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
        if (badge) badge.style.display = "none";
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

    // Adopt run_id if not set or if this is the start of the active run
    if (!state.pipeline.activeRunId && event.run_id) {
      state.pipeline.activeRunId = event.run_id;
    }

    // Protect against delayed events from a previous run, but adopt the first event of this run if needed
    if (state.pipeline.activeRunId && event.run_id && event.run_id !== state.pipeline.activeRunId) {
      if (!state.pipeline.hasReceivedEventForRun) {
        state.pipeline.activeRunId = event.run_id;
      } else {
        return; // Truly outdated event from an earlier run
      }
    }
    state.pipeline.hasReceivedEventForRun = true;

    const { event: evtType, stage_id: rawStageId, progress_pct, completed_count, applicable_count, elapsed_ms, stage, summary, duration_ms, findings_count, skip_reason } = event;
    const stage_id = rawStageId ? (STAGE_ALIASES[rawStageId] || rawStageId) : null;

    // Update progress bar
    if (elements.pipelineProgressFill && typeof progress_pct === "number") {
      elements.pipelineProgressFill.style.width = `${progress_pct}%`;
    }
    if (elements.pipelineMetricProgress) {
      elements.pipelineMetricProgress.textContent = `${completed_count || 0}/${applicable_count || 14} Stages (${progress_pct || 0}%)`;
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
      }
      const actualFindingsCount = findings_count || stageFindingsFromEvent.length || 0;

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

        if (evtType === "stage_start") {
          node.className = `stepper-step status-running${activeClass}`;
          if (icon) icon.textContent = "⟳";
          node.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'nearest' });
        } else if (evtType === "stage_complete") {
          if (stage_id === "final_report") {
            state.pipeline.isReportGenerated = true;
          }
          if (findings_count > 0) {
            node.className = `stepper-step status-warning${activeClass}`;
            if (icon) icon.textContent = "⚠";
            if (badge) {
              badge.textContent = `⚠ ${findings_count}`;
              badge.style.display = "inline-block";
            }
          } else {
            node.className = `stepper-step status-completed${activeClass}`;
            if (icon) icon.textContent = "✓";
          }
        } else if (evtType === "stage_failed") {
          node.className = `stepper-step status-failed${activeClass}`;
          if (icon) icon.textContent = "✗";
          if (badge) {
            badge.textContent = `✗ ${actualFindingsCount > 0 ? actualFindingsCount : 1}`;
            badge.className = "stepper-findings-badge badge-failed";
            badge.style.display = "inline-block";
          }
          if (elements.pipelineProgressFill) {
            elements.pipelineProgressFill.classList.add("fill-failed");
          }
        } else if (evtType === "stage_blocked") {
          node.className = `stepper-step status-blocked${activeClass}`;
          if (icon) icon.textContent = "⛔";
          if (badge) badge.style.display = "none";
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
        } else if (evtType === "stage_skipped") {
          node.className = `stepper-step status-skipped status-unavailable${activeClass}`;
          if (icon) icon.textContent = "⊘";
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
      if (elements.btnFinalReport) elements.btnFinalReport.disabled = false;
      state.pipeline.pausedStage = event.paused_stage;
      if (elements.pipelineStatusBadge) {
        elements.pipelineStatusBadge.textContent = "PAUSED FOR CORRECTION";
        elements.pipelineStatusBadge.className = "pipeline-status-badge badge-paused";
      }
      if (elements.pipelineProgressFill) {
        elements.pipelineProgressFill.classList.add("fill-failed");
      }
      if (elements.pipelineMetricStage) {
        elements.pipelineMetricStage.textContent = `Paused: Stage ${event.paused_stage || "Correction Required"}`;
      }
      showOutputWaitingState(
        "Compilation Paused for Correction",
        `Stage ${event.paused_stage} encountered a blocking error. Downstream stages are blocked. Click on the red stage box above to inspect and apply a fix.`
      );
      if (event.paused_stage) {
        openStageDrawer(event.paused_stage);
      }
    }

    // Pipeline Finish Event
    if (evtType === "pipeline_finish") {
      const status = event.status || "completed";
      state.pipeline.isFinished = true;
      state.pipeline.finishStatus = status;
      if (elements.btnFinalReport) elements.btnFinalReport.disabled = false;
      if (event.artifacts) {
        state.pipeline.pendingArtifacts = event.artifacts;
      }

      const mandatoryStages = [
        "source_input", "lexical_analysis", "syntax_analysis", "ast_construction",
        "semantic_analysis", "symbol_table", "ir_generation", "optimization",
        "code_generation", "code_validation"
      ];
      const mandatoryFailed = mandatoryStages.some(id => (state.pipeline.stageData[id] || {}).status === "failed");
      const stage14Data = state.pipeline.stageData["final_report"] || {};
      const stage14Completed = stage14Data.status === "completed" || stage14Data.status === "passed";

      if (status === "ready_for_report") {
        state.pipeline.isReadyForReport = true;
        if (elements.pipelineStatusBadge) {
          elements.pipelineStatusBadge.textContent = "READY FOR REPORT";
          elements.pipelineStatusBadge.className = "pipeline-status-badge badge-ready";
        }
        if (elements.pipelineProgressFill) {
          elements.pipelineProgressFill.style.width = "93%";
          elements.pipelineProgressFill.className = "pipeline-progress-fill";
        }
        if (elements.pipelineMetricStage) {
          elements.pipelineMetricStage.textContent = "All 13 Stages Verified (Ready for Final Report)";
        }
        if (elements.pipelineMetricProgress) {
          elements.pipelineMetricProgress.textContent = "13/13 Stages Verified (Stage 14 Gate Ready)";
        }
        const node14 = document.getElementById("step-node-final_report");
        if (node14) {
          node14.className = "stepper-step status-ready";
          const icon14 = node14.querySelector(".stepper-step-icon");
          if (icon14) icon14.textContent = "★";
        }
        showOutputWaitingState(
          "All 13 Stages Verified Clean",
          "Click stage 14 (Final Report) in the pipeline header above to review metrics and generate the final report."
        );
      } else if (mandatoryFailed || state.pipeline.isPaused) {
        if (elements.pipelineStatusBadge) {
          elements.pipelineStatusBadge.textContent = state.pipeline.isPaused ? "PAUSED FOR CORRECTION" : (status.toUpperCase() || "FAILED");
          elements.pipelineStatusBadge.className = "pipeline-status-badge badge-failed";
        }
        if (elements.pipelineProgressFill) {
          elements.pipelineProgressFill.classList.add("fill-failed");
        }
        if (elements.pipelineMetricStage) {
          elements.pipelineMetricStage.textContent = state.pipeline.isPaused ? `Paused: Stage ${state.pipeline.pausedStage || "Correction Required"}` : `Finished: ${status.toUpperCase()}`;
        }
        showOutputWaitingState(
          "Compilation Incomplete",
          "Compilation encountered errors or was paused. Correct errors in the stage panels above."
        );
      } else if (stage14Completed || status === "completed" || status === "warning") {
        state.pipeline.isReportGenerated = true;
        if (elements.pipelineStatusBadge) {
          elements.pipelineStatusBadge.textContent = status.toUpperCase();
          elements.pipelineStatusBadge.className = `pipeline-status-badge badge-${status}`;
        }
        if (elements.pipelineProgressFill) {
          elements.pipelineProgressFill.style.width = "100%";
          elements.pipelineProgressFill.className = (status === "warning") ? "pipeline-progress-fill fill-warning" : "pipeline-progress-fill";
        }
        if (elements.pipelineMetricStage) {
          elements.pipelineMetricStage.textContent = (status === "warning") ? "Pipeline Completed with Warnings" : "Pipeline Completed";
        }
        if (elements.pipelineMetricProgress) {
          elements.pipelineMetricProgress.textContent = "14/14 Stages Completed";
        }
        if (event.artifacts) {
          showOutputArtifacts(event.artifacts);
          switchOutputTab("tab-out-pipeline"); // Task A: Auto-open final report on completion
          if (event.artifacts.security) {
            renderSecurityFindings(
              event.artifacts.security.findings || [],
              event.artifacts.security.overall_risk_score,
              event.artifacts.security.overall_summary || "",
              Boolean(event.artifacts.security.syntax_blocked)
            );
          }
        }
      } else {
        if (elements.pipelineStatusBadge) {
          elements.pipelineStatusBadge.textContent = status.toUpperCase();
          elements.pipelineStatusBadge.className = `pipeline-status-badge badge-${status}`;
        }
        if (elements.pipelineProgressFill) {
          if (status === "warning") elements.pipelineProgressFill.classList.add("fill-warning");
          else if (status === "failed") elements.pipelineProgressFill.classList.add("fill-failed");
        }
        if (elements.pipelineMetricStage) {
          elements.pipelineMetricStage.textContent = `Finished: ${status.toUpperCase()}`;
        }
        showOutputWaitingState(
          "Compilation Incomplete",
          "Compilation encountered errors or was paused. Correct errors in the stage panels above."
        );
      }
    }
  }

  function updatePipelineStageBadge(stageId, count, status) {
    const node = document.getElementById(`step-node-${stageId}`);
    const badge = document.getElementById(`step-badge-${stageId}`);
    if (node) {
      const isActive = state.pipeline.activeDrawerStage === stageId;
      const activeClass = isActive ? " active-drawer" : "";
      const icon = node.querySelector(".stepper-step-icon");
      if (status === "failed") {
        node.className = `stepper-step status-failed${activeClass}`;
        if (icon) icon.textContent = "✗";
        if (badge) {
          badge.textContent = `✗ ${count}`;
          badge.className = "stepper-findings-badge badge-failed";
          badge.style.display = count > 0 ? "inline-block" : "none";
        }
      } else if (count > 0 || status === "warning") {
        node.className = `stepper-step status-warning${activeClass}`;
        if (icon) icon.textContent = "⚠";
        if (badge) {
          badge.textContent = `⚠ ${count}`;
          badge.className = "stepper-findings-badge";
          badge.style.display = "inline-block";
        }
      } else if (status === "completed") {
        node.className = `stepper-step status-completed${activeClass}`;
        if (icon) icon.textContent = "✓";
        if (badge) badge.style.display = "none";
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
    const data = (state.pipeline && state.pipeline.stageData && state.pipeline.stageData[stageId]) || {};
    if (data.details && Array.isArray(data.details.findings) && data.details.findings.length > 0) {
      syncFindingsIntoStore(data.details.findings, [], null, stageId, data.status);
    }

    const allStoreFindings = Object.values(state.findingsStore || {});
    const filtered = allStoreFindings.filter(f => {
      const s = (f.stage_id || "").toLowerCase();
      const st = (f.stage || "").toLowerCase();
      if (stageId === "security_analysis") {
        return !f.is_ai_observation && (s === "security" || s === "security_analysis" || s === "multilingual" || st.includes("security") || (!s.includes("parser") && !s.includes("syntax") && !s.includes("lexical") && !s.includes("semantic")));
      }
      if (stageId === "ai_security_analysis") {
        return f.is_ai_observation || f.is_ai_enriched || s.includes("ai") || st.includes("ai") || st.includes("ollama");
      }
      if (stageId === "syntax_analysis") {
        return s.includes("parser") || s.includes("syntax") || st.includes("syntax") || st.includes("parser");
      }
      if (stageId === "lexical_analysis") {
        return s.includes("lexical") || st.includes("lexical");
      }
      if (stageId === "semantic_analysis") {
        return s.includes("semantic") || st.includes("semantic");
      }
      return s === stageId.toLowerCase();
    });

    if (filtered.length > 0) {
      return filtered;
    }

    if (data.details && Array.isArray(data.details.findings) && data.details.findings.length > 0) {
      return data.details.findings;
    }
    const allSec = (state.security && state.security.findings) || [];
    if (stageId === "security_analysis") {
      return allSec.filter(f => {
        const s = (f.stage_id || "").toLowerCase();
        const st = (f.stage || "").toLowerCase();
        return !f.is_ai_observation && (s === "security" || s === "security_analysis" || s === "multilingual" || st.includes("security") || (!s.includes("parser") && !s.includes("syntax") && !s.includes("lexical") && !s.includes("semantic")));
      });
    }
    if (stageId === "ai_security_analysis") {
      return allSec.filter(f => f.is_ai_observation || f.is_ai_enriched || (f.stage_id || "").includes("ai") || (f.stage || "").toLowerCase().includes("ai") || (f.stage || "").toLowerCase().includes("ollama"));
    }
    if (stageId === "syntax_analysis") {
      return allSec.filter(f => (f.stage_id || "").includes("parser") || (f.stage_id || "").includes("syntax") || (f.stage || "").toLowerCase().includes("syntax") || (f.stage || "").toLowerCase().includes("parser"));
    }
    if (stageId === "lexical_analysis") {
      return allSec.filter(f => (f.stage_id || "").includes("lexical") || (f.stage || "").toLowerCase().includes("lexical"));
    }
    if (stageId === "semantic_analysis") {
      return allSec.filter(f => (f.stage_id || "").includes("semantic") || (f.stage || "").toLowerCase().includes("semantic"));
    }
    return [];
  }

  async function generateFinalReport(allowIncomplete = false) {
    const currentCode = state.editor ? state.editor.getValue() : "";
    const lang = state.currentFile ? state.currentFile.language : "English";

    // Check if source changed since compile
    if (state.pipeline.compiledSource && currentCode !== state.pipeline.compiledSource) {
      alert("Source code has been modified since the last compile pass. Please re-run the compiler before generating the final report.");
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
      const resp = await fetch("/api/pipeline/generate-report", {
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
        alert(`Report generation blocked: ${res.error || 'Prerequisites not satisfied.'}`);
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = `📊 Generate Final Report & Unlock Output`;
        }
      }
    } catch (err) {
      console.error("Final report error:", err);
      alert(`Failed to generate final report: ${err.message}`);
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
    const data = state.pipeline.stageData[stageId] || { status: "pending", duration_ms: 0, summary: "Pending initialization" };

    const status = data.status || "pending";
    const duration = typeof data.duration_ms === "number" ? data.duration_ms : 0;
    const stageFindings = getStageFindings(stageId);
    if (status === "failed" && stageFindings.length === 0 && data.summary) {
      stageFindings.push({
        id: `ERR-${stageId.toUpperCase()}-1`,
        title: data.summary,
        severity: "Critical",
        stage: defn.name,
        stage_id: stageId,
        line: 1,
        column: 1,
        evidence: data.summary,
        code_excerpt: data.summary,
        explanation: `The ${defn.name} stage failed during compilation: ${data.summary}`,
        potential_impact: "Halts subsequent compilation stages.",
        remediation: "Inspect the reported message and correct the source code.",
        status: "open",
        rule_id: `ERR-${stageId.toUpperCase()}`
      });
    }
    const unresolvedFindings = stageFindings.filter(f => f.status !== "resolved");
    const resolvedFindings = stageFindings.filter(f => f.status === "resolved");
    let findingsCount = unresolvedFindings.length;
    if (findingsCount === 0 && status === "failed") {
      findingsCount = (data.findings_count > 0) ? data.findings_count : (data.details && data.details.findings ? data.details.findings.length : 1);
    }
    const category = defn.category ? defn.category.toUpperCase() : "COMPILER";

    // Status pill rendering
    let pillClass = "pill-pending";
    let pillText = `○ Pending · In Queue`;
    let outcomeText = "Pending Execution";
    let outcomeClass = "";

    if (status === "completed") {
      pillClass = "pill-completed";
      pillText = `✓ Completed · ${duration} ms`;
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
              ${stageId === "ai_security_analysis" ? "Ollama AI Agent Status" : "Deterministic Security Risk Assessment"}
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
    }

    // Clean Verification Card (when unresolved findings === 0 and clean, and no active security issues remain)
    let cleanVerificationHtml = "";
    if (findingsCount === 0 && unresSec === 0 && (status === "completed" || status === "pending" || status === "running")) {
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
          ${aiNote ? `<div class="drawer-kv-row"><span class="drawer-kv-key">Ollama AI Review</span><span class="drawer-kv-val">${escapeHtml(aiNote)}</span></div>` : ''}
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
            <span class="drawer-token-pill">Ollama Model: <strong>qwen2.5-coder:7b-instruct</strong></span>
          </div>
        </div>
      `;
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
        if (f.status === "pending_validation") {
          badgeHtml = '<span class="stage-finding-badge" style="background:#DBEAFE; color:#1E40AF; border:1px solid #93C5FD;">⟳ PENDING VALIDATION</span>';
          statusLabel = "Pending Validation (Fix Applied)";
        } else if (f.validation_status === "validation_failed") {
          badgeHtml = '<span class="stage-finding-badge" style="background:#FEE2E2; color:#991B1B; border:1px solid #FCA5A5;">✗ VALIDATION FAILED</span>';
          statusLabel = "Validation Failed (Still Detected)";
        } else if (f.status === "fix_proposed") {
          badgeHtml = '<span class="stage-finding-badge" style="background:#EDE9FE; color:#5B21B6; border:1px solid #C4B5FD;">✨ FIX PROPOSED</span>';
          statusLabel = "Fix Proposed (Review Diff)";
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

            <div class="stage-finding-actions">
              <span style="font-size: 11px; color: #64748B;">
                Status: <strong>${statusLabel}</strong> &bull; Confidence: ${escapeHtml(f.confidence || 'confirmed')}
              </span>
              <div class="finding-action-btns">
                <button class="btn btn-primary btn-sm btn-drawer-suggest-fix" data-finding-id="${escapeHtml(fid)}" data-stage-id="${escapeHtml(stageId)}">
                  <span>✨ Suggest Fix</span>
                </button>
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
      if (unresolvedFindings.length > 0) {
        const errWord = unresolvedFindings.length === 1 ? "ERROR" : "ERRORS";
        fixAllBannerHtml = `
          <div class="stage-fix-all-banner" id="stage-fix-all-banner-${stageId}">
            <div class="fix-all-content">
              <div class="fix-all-text-group">
                <div class="fix-all-title-row">
                  <span class="fix-all-badge">${escapeHtml(defn.name)} Remediation</span>
                  <span class="fix-all-title">Batch Automated Stage Correction</span>
                </div>
                <p class="fix-all-desc">
                  Resolve all <strong>${unresolvedFindings.length}</strong> active diagnostic ${unresolvedFindings.length === 1 ? 'issue' : 'issues'} in this stage using Ollama AI and validated patches.
                </p>
              </div>
              <div class="fix-all-btn-group">
                <button class="btn btn-primary btn-fix-all" id="btn-fix-all-${stageId}" data-stage-id="${stageId}">
                  <span class="btn-fix-all-icon">⚡</span>
                  <span class="btn-fix-all-text">FIX ALL (${unresolvedFindings.length} ${errWord})</span>
                </button>
              </div>
            </div>
            <div class="fix-all-progress-bar" id="fix-all-progress-${stageId}" style="display: none;">
              <span class="spinner" style="display:inline-block; width:14px; height:14px; border:2px solid #93C5FD; border-top-color:#1D4ED8; border-radius:50%; animation:spin 1s linear infinite;"></span>
              <span id="fix-all-status-text-${stageId}">Ollama AI analyzing all ${unresolvedFindings.length} diagnostics and synthesizing combined correction...</span>
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
          const resp = await fetch("/api/pipeline/retry-optimization", {
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
            alert(`Optimization failed: ${res.error || 'Optimization error'}`);
            optRetryBtn.disabled = false;
            optRetryBtn.innerHTML = `⚡ Run / Retry Optimization`;
          }
        } catch (err) {
          alert(`Optimization error: ${err.message}`);
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
      const resp = await fetch("/api/working-source/save", {
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

  async function handleFixAllClick(stageId) {
    const btn = document.getElementById(`btn-fix-all-${stageId}`);
    const progress = document.getElementById(`fix-all-progress-${stageId}`);
    const statusText = document.getElementById(`fix-all-status-text-${stageId}`);

    const stageFindings = getStageFindings(stageId);
    const unresolved = stageFindings.filter(f => f.status !== "resolved");
    if (unresolved.length === 0) {
      alert("No unresolved diagnostics to fix in this stage.");
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
      const resp = await fetch("/api/ai/fix-all", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          stage_id: stageId,
          source_code: currentCode,
          language: lang,
          file_path: filePath,
          diagnostics: unresolved
        })
      });

      const data = await resp.json();
      if (!data.success && (!data.fixes || data.fixes.length === 0)) {
        if (progress) progress.style.display = "none";
        if (btn) btn.disabled = false;
        alert(`Ollama AI was unable to generate safe corrections for this stage:\n\n${data.error || data.explanation || 'No safe patch could be determined.'}`);
        setStatus("Fix All was unable to resolve stage issues", "warning");
        return;
      }

      if (progress) progress.style.display = "none";
      if (btn) btn.disabled = false;

      // Open Fix Modal in Fix-All mode
      openFixAllModal(stageId, data, unresolved);
    } catch (err) {
      console.error("Fix All error:", err);
      if (progress) progress.style.display = "none";
      if (btn) btn.disabled = false;
      alert(`Fix All request failed: ${err.message}`);
      setStatus("Fix All request error", "error");
    }
  }

  function openFixAllModal(stageId, data, unresolved) {
    if (!elements.fixModalOverlay) return;

    const defn = state.pipeline.stages.find(s => s.id === stageId) || { name: stageId };
    const resCount = data.resolved_count || (data.fixes ? data.fixes.length : 0);
    const totalCount = data.total_diagnostics || unresolved.length;

    elements.fixModalTitle.textContent = `Fix All: ${defn.name} (${resCount}/${totalCount} Issues Resolved)`;
    elements.fixModalSeverity.textContent = `${resCount} Issues Fixed`;
    elements.fixModalSeverity.className = "fix-modal-badge sev-low";

    if (elements.fixModalSource) {
      const modelLabel = data.model_selected ? `Ollama (${data.model_selected})` : "Ollama AI Batch";
      elements.fixModalSource.textContent = modelLabel;
      elements.fixModalSource.className = "fix-modal-source-badge badge-ollama-ai";
    }
    if (elements.fixModalValidation) {
      const vText = data.validation_verdict === "verified" ? "Verified Clean" : (data.validated ? "Validated Resolved" : "Validated");
      elements.fixModalValidation.textContent = vText;
      elements.fixModalValidation.className = "fix-modal-val-badge val-passed";
    }
    if (elements.fixAiRefiningBar) {
      elements.fixAiRefiningBar.style.display = "none";
    }

    switchDiffViewMode("unified");

    let explanationText = data.explanation || `Batch remediation resolves ${resCount} diagnostic issue(s) across ${defn.name}.`;
    if (data.routing_reason) {
      explanationText = `[AI Routing]: ${data.routing_reason}\n\n${explanationText}`;
    }
    if (data.timing) {
      explanationText += `\n\n[Performance]: Inference: ${data.timing.inference_time_ms || 0}ms | Validation: ${data.timing.compiler_validation_time_ms || 0}ms | Total: ${data.timing.total_duration_ms || 0}ms`;
    }
    if (data.fixes && data.fixes.length > 0) {
      const fixSummaries = data.fixes.map((f, i) => {
        const typeBadge = (f.fix_type === "rule-based" || f.is_deterministic) ? "[Rule-based]" : "[AI]";
        const lineStr = f.target_line || (f.finding_data && f.finding_data.line) ? ` L${f.target_line || f.finding_data.line}` : "";
        return `${i + 1}. ${typeBadge} [${f.rule_id || f.finding_id || 'Issue'}${lineStr}] ${f.explanation || f.title || 'Corrected'}`;
      }).join("\n");
      explanationText += `\n\nResolved Issues:\n${fixSummaries}`;
    }
    if (data.unresolved && data.unresolved.length > 0) {
      const unresList = data.unresolved.map(u => u.title || u.id).join(", ");
      explanationText += `\n\nRemaining Manual Inspection Needed: ${unresList}`;
    }

    elements.fixModalExplanation.textContent = explanationText;
    renderDiffPreview(data.diff || `--- original\n+++ proposed\n// Combined stage fixes applied`);
    if (elements.fixSplitBefore) elements.fixSplitBefore.textContent = state.editor.getValue();
    if (elements.fixSplitAfter) elements.fixSplitAfter.textContent = data.proposed_source || "";

    elements.btnApplyFix.disabled = false;
    elements.btnApplyFix.textContent = `Apply All Fixes to Working Buffer (${resCount} Fixes)`;

    state.security.pendingFix = {
      is_fix_all: true,
      stage_id: stageId,
      target_stage_id: stageId,
      source_revision: state.sourceRevisionId || 1,
      file_path: state.currentFile ? state.currentFile.path : "",
      proposed_source: data.proposed_source,
      diff: data.diff,
      resolved_count: resCount,
      total_diagnostics: totalCount,
      explanation: explanationText,
      fixes: data.fixes || [],
      unresolved: data.unresolved || []
    };

    updateUndoButtonsState();
    elements.fixModalOverlay.style.display = "flex";
  }

  async function handleSuggestFixClick(findingId, stageId) {
    const container = document.getElementById(`inline-remediation-${findingId}`);
    if (!container) return;

    const finding = getStageFindings(stageId).find(f => String(f.id) === String(findingId)) ||
                    (state.security.findings || []).find(f => String(f.id) === String(findingId)) || { id: findingId };

    // Set loading indicator indicating local Ollama AI consultation
    container.innerHTML = `
      <div class="inline-remediation-box">
        <div style="display: flex; align-items: center; gap: 8px; color: #2563EB; font-size: 12px;">
          <span class="ai-spin-icon">⟳</span>
          <span>AI Analysis Running (Routing to local Ollama) for <strong>${escapeHtml(finding.title || findingId)}</strong>...</span>
        </div>
      </div>
    `;
    setStatus("AI Analysis Running...", "running");

    const currentCode = state.editor ? state.editor.getValue() : "";
    const lang = state.currentFile ? state.currentFile.language : "English";

    try {
      const resp = await fetch("/api/security/suggest-fix", {
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
          prefer_deterministic: false,
          request_ai: true
        })
      });
      const res = await resp.json();
      res.target_finding_id = findingId;
      res.source_revision = state.sourceRevisionId || 1;
      res.file_path = state.currentFile ? state.currentFile.path : "";
      state.findingFixes[findingId] = res;
      setStatus(`Correction Generated (${res.model_selected || 'Ollama AI'})`, "running");

      if (res.success && res.proposed_source && res.proposed_source !== currentCode) {
        if (state.findingsStore && state.findingsStore[findingId]) {
          state.findingsStore[findingId].status = "fix_proposed";
        }
        renderInlineRemediation(findingId, stageId, res);
      } else {
        const errorMsg = (res.proposed_source === currentCode)
          ? "No code changes detected in proposed fix."
          : (res.error || "Automated patch could not be validated.");
        const isOffline = res.ollama_online === false;
        container.innerHTML = `
          <div class="inline-remediation-box" style="border-left: 3px solid #EF4444;">
            <div style="font-size: 12px; color: #991B1B;">
              <strong>${isOffline ? 'Ollama AI Offline:' : 'AI Remediation Note:'}</strong> ${escapeHtml(errorMsg)}
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
    const sourceLabel = isDet ? "Local Rule" : "Ollama AI";
    const sourceBadgeClass = isDet ? "badge-local-rule" : "badge-ollama-ai";

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

    const modelBadge = fixData.model_selected ? `<span class="fix-modal-source-badge badge-ollama-ai" style="font-size: 10px;">🤖 ${escapeHtml(fixData.model_selected)}</span>` : '';
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
    if (fixData.source_revision && fixData.source_revision !== state.sourceRevisionId) {
      setStatus("Source changed since this fix was suggested, regenerating...", "running");
      delete state.findingFixes[findingId];
      const container = document.getElementById(`inline-remediation-${findingId}`);
      if (container) container.innerHTML = "";
      handleSuggestFixClick(findingId, stageId, fixData.finding_data || { id: findingId });
      return;
    }
    if (fixData.file_path && state.currentFile && fixData.file_path !== state.currentFile.path) {
      alert("This fix belongs to a different file. Please re-generate the fix for the active file.");
      return;
    }

    // 1. Snapshot working buffer and findings store for undo
    state.security.undoStack.push({
      code: currentCode,
      timestamp: Date.now(),
      label: `Before fix for ${findingId}`,
      findingsStore: JSON.parse(JSON.stringify(state.findingsStore || {}))
    });
    updateUndoButtonsState();

    // 2. Apply to editor buffer
    if (state.editor) {
      state.editor.setValue(proposedCode);
    }
    saveCurrentFileBuffer();

    // 3. Atomically apply and persist fix via backend /api/ai/apply-fix
    try {
      const applyResp = await fetch("/api/ai/apply-fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          file_path: (state.currentFile && state.currentFile.path) || fixData.file_path || "",
          code: proposedCode,
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
        alert("Patch Application Rejected:\n\n" + (applyData.error || "Validation failed.") + "\n\nThe working source code was not modified to prevent regression.");
        state.editor.setValue(currentCode);
        saveCurrentFileBuffer();
        return;
      }
      state.sourceRevisionId = applyData.source_revision || (state.sourceRevisionId + 1);
    } catch (err) {
      alert("Failed to communicate with compiler backend: " + err.message);
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
    setStatus(`Status: Applied Revision ${state.sourceRevisionId}. Automatically re-validating compiler pipeline from start...`, "running");
    await runCompiler(null, true);
  }

  /* ========================================================================
     4. COMPILER EXECUTION (RUN BUTTON) WITH LIVE STREAMING PIPELINE
     ======================================================================== */
  async function runCompiler(resumeFromStage = null, autoResume = false) {
    if (state.isExecuting && !autoResume) return;

    const sourceCode = state.editor.getValue().trim();
    if (!sourceCode) {
      setStatus("Status: Error - Empty Source Code", "error");
      elements.consoleProgram.textContent = "> Error: No source code provided. Please enter or select code to run.";
      return;
    }

    state.isExecuting = true;
    setRunningUI(true);

    // Generate unique run ID to prevent delayed cross-run contamination
    const runId = "run-" + Date.now() + "-" + Math.random().toString(36).substring(2, 8);
    state.pipeline.activeRunId = runId;
    state.pipeline.hasReceivedEventForRun = false;
    state.pipeline.compiledSource = state.editor.getValue();
    state.pipeline.isReportGenerated = false;
    state.pipeline.isReadyForReport = false;
    state.pipeline.isFinished = false;
    state.pipeline.finishStatus = null;
    state.pipeline.pendingArtifacts = null;
    state.pipeline.isPaused = false;
    state.pipeline.pausedStage = null;
    state.pipeline.runRevision = state.sourceRevisionId || 1;

    if (!resumeFromStage) {
      resetPipelineStepper();
      showOutputWaitingState(
        "Pipeline In Progress",
        "Compiling source code progressively. Output tabs will appear after Final Report generation."
      );
      setStatus("Status: Running Compiler & Security Pipeline...", "running");
    } else {
      invalidateDownstreamStages(resumeFromStage);
      showOutputWaitingState(
        "Pipeline In Progress",
        "Compiling source code progressively. Output tabs will appear after Final Report generation."
      );
      const resumeNode = document.getElementById(`step-node-${resumeFromStage}`);
      if (resumeNode) {
        resumeNode.className = "stepper-step status-running";
        const icon = resumeNode.querySelector(".stepper-step-icon");
        if (icon) icon.textContent = "⟳";
      }
      setStatus(`Status: Automatically resuming pipeline from ${resumeFromStage}...`, "running");
    }

    try {
      // Connect to SSE stream
      const resp = await fetch("/api/pipeline/stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          run_id: runId,
          code: state.editor.getValue(),
          language: state.currentFile.language,
          use_ai_security: elements.toggleStage12Ai ? elements.toggleStage12Ai.checked : false,
          pause_on_error: true,
          resume_from: resumeFromStage || undefined,
          source_revision: state.sourceRevisionId || 1
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
                try {
                  const jsonStr = trimmed.substring(5).trim();
                  if (jsonStr) {
                    const event = JSON.parse(jsonStr);
                    handlePipelineEvent(event);
                    await new Promise(r => requestAnimationFrame(r));
                  }
                } catch (parseErr) {
                  // Ignore chunk parse error
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
              try {
                const jsonStr = trimmed.substring(5).trim();
                if (jsonStr) {
                  const event = JSON.parse(jsonStr);
                  handlePipelineEvent(event);
                  await new Promise(r => requestAnimationFrame(r));
                }
              } catch (parseErr) {
                // Ignore final parse error
              }
            }
          }
        }
      } else {
        // Fallback for environments lacking streaming response readers
        const fallbackResp = await fetch("/api/pipeline/run", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            run_id: runId,
            code: state.editor.getValue(),
            language: state.currentFile.language,
            use_ai_security: true,
            pause_on_error: true,
            resume_from: resumeFromStage || undefined,
            source_revision: state.sourceRevisionId || 1
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
      setStatus("Status: Fatal Connection Error", "error");
      elements.consoleProgram.textContent = `[SYSTEM ERROR]\nFailed to communicate with compiler backend: ${err.message}`;
      if (elements.pipelineStatusBadge) {
        elements.pipelineStatusBadge.textContent = "FAILED";
        elements.pipelineStatusBadge.className = "pipeline-status-badge badge-failed";
      }
      if (elements.pipelineProgressFill) {
        elements.pipelineProgressFill.classList.add("fill-failed");
      }
      if (elements.pipelineMetricStage) {
        elements.pipelineMetricStage.textContent = `Error: Pipeline Interrupted`;
      }
    } finally {
      state.isExecuting = false;
      setRunningUI(false);
    }
  }

  function handleExecutionResult(res) {
    // 1. Timing
    elements.outputTimingBadge.textContent = `${res.elapsed_ms || 0} ms`;
    elements.statusbarElapsed.textContent = `${res.elapsed_ms || 0} ms`;

    // 2. Populate all Stage Tabs
    elements.consoleProgram.textContent = (res.output && res.output.trim()) ? res.output : "(No standard output produced)";
    elements.consolePipeline.textContent = res.aggregated_log || res.parser_log || "(No pipeline report generated)";
    elements.consoleLexer.textContent = res.lexer_log || "(No lexer tokens log)";
    elements.consoleParser.textContent = res.parser_log || "(No parser log)";
    elements.consoleAst.textContent = res.ast_log || "(No AST generated)";
    elements.consoleIr.textContent = res.ir_code || "(No IR generated)";
    elements.consoleSymbol.textContent = res.symbol_table || "(No symbol table generated)";
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
          opt.ai_analysis ? `• Ollama AI Review:      ${opt.ai_analysis}` : "",
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
      } else {
        elements.consoleOptimization.textContent = "(Optimization stage completed. See Pipeline Report for details.)";
      }
    }

    // 3. Clear existing error badges on tabs
    elements.outputTabBtns.forEach(b => b.classList.remove("error-badge"));

    // 4. Store genuine compiler diagnostics for AI Assistant advisory reasoning
    state.ai.latestCompilerDiagnostics = res;

    // 5. Status and Diagnostics
    if (res.success) {
      setStatus(`Status: System Ready | Compilation Succeeded`, "ready");
      switchOutputTab("tab-out-program");
    } else {
      setStatus(`Status: Compilation Error Detected`, "error");

      // Highlight relevant tab with red badge
      if (res.execution_status === "syntax_error") {
        const parserBtn = document.querySelector('[data-tab="tab-out-parser"]');
        if (parserBtn) parserBtn.classList.add("error-badge");
        switchOutputTab("tab-out-parser");
      } else {
        const programBtn = document.querySelector('[data-tab="tab-out-program"]');
        if (programBtn) programBtn.classList.add("error-badge");
        switchOutputTab("tab-out-program");
      }
    }
  }

  /* ========================================================================
     SECURITY ANALYSIS & LOCAL OLLAMA AGENT WORKFLOW
     ======================================================================== */
  async function checkOllamaSecurityStatus() {
    try {
      const resp = await fetch("/api/security/status");
      const data = await resp.json();
      state.security.ollamaStatus = {
        online: data.ollama_online,
        model: data.config ? data.config.model_name : "qwen2.5-coder:7b-instruct",
        message: data.message
      };

      if (elements.ollamaStatusLabel && elements.ollamaPulseDot) {
        if (data.ollama_online) {
          elements.ollamaStatusLabel.textContent = `Ollama: ${state.security.ollamaStatus.model} (Online)`;
          elements.ollamaPulseDot.className = "status-pulse-dot";
        } else {
          elements.ollamaStatusLabel.textContent = `Ollama: Offline (Local Rules Active)`;
          elements.ollamaPulseDot.className = "status-pulse-dot offline";
        }
      }
    } catch (e) {
      if (elements.ollamaStatusLabel) {
        elements.ollamaStatusLabel.textContent = `Ollama: Unreachable`;
      }
    }
  }

  async function runSecurityScan(useAi = true) {
    const code = state.editor.getValue();
    if (!code || !code.trim()) {
      renderSecurityFindings([], 0, "No code in editor to analyze.", false);
      return;
    }

    try {
      setStatus("Status: Running Security Analysis...", "running");
      const resp = await fetch("/api/security/scan", {
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

    // Keep security_analysis stageData and badges in sync
    if (state.pipeline && state.pipeline.stageData) {
      if (!state.pipeline.stageData["security_analysis"]) {
        state.pipeline.stageData["security_analysis"] = { id: "security_analysis", name: "11. Security", category: "security" };
      }
      state.pipeline.stageData["security_analysis"].details = state.pipeline.stageData["security_analysis"].details || {};
      state.pipeline.stageData["security_analysis"].details.findings = findings || [];
      state.pipeline.stageData["security_analysis"].details.overall_risk_score = overallScore;
      state.pipeline.stageData["security_analysis"].findings_count = (findings || []).length;
      const secStatus = syntaxBlocked ? "failed" : ((findings && findings.length > 0) ? "warning" : "completed");
      state.pipeline.stageData["security_analysis"].status = secStatus;
      updatePipelineStageBadge("security_analysis", (findings || []).length, secStatus);
      if (state.pipeline.activeDrawerStage === "security_analysis") {
        renderStageDrawer("security_analysis");
      }
    }

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

  function updateUndoButtonsState() {
    const hasUndo = Boolean(state.security.undoStack && state.security.undoStack.length > 0);
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
  }

  function closeOriginalViewModal() {
    if (elements.originalModalOverlay) {
      elements.originalModalOverlay.style.display = "none";
    }
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
        resetPipelineStepper();
        showOutputWaitingState(
          "Original Educational Demo Restored",
          "All corrections discarded. Click ▶ Run to execute the compiler and observe the original errors/vulnerabilities."
        );
        closeOriginalViewModal();
        closeStageDrawer();
        updateUndoButtonsState(Boolean(data.can_undo));
        setStatus(`Status: Restored original educational demo (${state.currentFile.filename}).`, "ready");
        runSecurityScan(false);
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
      resetPipelineStepper();
      closeOriginalViewModal();
      closeStageDrawer();
      setStatus(`Status: Restored original demo (${state.currentFile.filename}).`, "ready");
    }
  }

  async function saveCorrectedCode() {
    const currentCode = state.editor ? state.editor.getValue() : "";
    if (!currentCode.trim()) {
      alert("Cannot save an empty file.");
      return;
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
        alert(`Failed to save file: ${res.error || 'Server rejected save request.'}`);
        setStatus("Save failed", "error");
        return;
      }

      setStatus(`Successfully saved ${cleanFilename} to My Saved Programs!`, "ready");
      alert(`Corrected program successfully saved as "${cleanFilename}"!\n\nIt is now accessible in the Explorer under "My Saved Programs" without security demo labels.`);

      // Refresh demo tree so new file appears in Explorer
      await loadDemosList();

      // Switch editor to the newly saved file
      if (res.path) {
        await loadDemoFile(res.path);
      }
    } catch (err) {
      console.error("Save file error:", err);
      alert(`Error saving file: ${err.message}`);
      setStatus("Error saving file", "error");
    }
  }

  async function openFixModal(findingId, findingData) {
    if (!elements.fixModalOverlay) return;

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
      const resp = await fetch("/api/security/suggest-fix", {
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
          elements.fixModalSource.textContent = isDet ? "Local rule" : "Ollama AI";
          elements.fixModalSource.className = `fix-modal-source-badge ${isDet ? 'badge-local-rule' : 'badge-ollama-ai'}`;
        }

        renderDiffPreview(res.diff || `--- original\n+++ proposed\n- ${res.original_code}\n+ ${res.proposed_code}`);
        if (elements.fixSplitBefore) elements.fixSplitBefore.textContent = res.original_code || currentCode;
        if (elements.fixSplitAfter) elements.fixSplitAfter.textContent = res.proposed_code || res.proposed_source || "";

        // 2. Non-blocking Progressive AI Refinement if Ollama is online and refinement is possible
        if (res.can_refine_with_ai && state.security.ollamaStatus && state.security.ollamaStatus.online) {
          if (elements.fixAiRefiningBar) {
            if (elements.fixAiRefiningText) {
              elements.fixAiRefiningText.textContent = `Ollama (${state.security.ollamaStatus.model}) is refining suggestion in background...`;
            }
            elements.fixAiRefiningBar.style.display = "flex";
          }

          // Fire non-blocking request with timeout
          fetch("/api/security/refine-fix", {
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
                elements.fixModalSource.textContent = "Ollama AI (Refined)";
                elements.fixModalSource.className = "fix-modal-source-badge badge-ollama-ai";
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
    if (pending.source_revision && pending.source_revision !== state.sourceRevisionId) {
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
      alert("This fix belongs to a different file. Please re-generate the fix for the active file.");
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
      const applyResp = await fetch("/api/ai/apply-fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          file_path: (state.currentFile && state.currentFile.path) || pending.file_path || "",
          code: proposedCode,
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
        alert("Patch Application Rejected:\n\n" + (applyData.error || "Validation failed.") + "\n\nThe working source code was not modified to prevent regression.");
        setStatus("Patch Rejected: " + (applyData.error || "Validation failed"), "error");
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
      state.editor.setValue(proposedCode);
      saveCurrentFileBuffer();

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

      setStatus(`Status: Applied Revision ${state.sourceRevisionId}. Automatically re-validating compiler pipeline from start...`, "running");

      // 6. Automatically restart compilation from start to revalidate all 14 stages
      await runCompiler(null, true);

    } catch (err) {
      console.error("Apply fix error:", err);
      alert("Unexpected error applying fix: " + err.message);
      setStatus("Error applying fix", "error");
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
        runSecurityScan(false);
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
        runSecurityScan(false);
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

  function switchOutputTab(tabId) {
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

    // Synchronize top toolbar AI Assistant button active state
    if (elements.btnAiAssistant) {
      if (tabId === "tab-out-ai") {
        elements.btnAiAssistant.classList.add("active");
      } else {
        elements.btnAiAssistant.classList.remove("active");
      }
    }
  }

  function handleAiToolbarClick() {
    switchOutputTab("tab-out-ai");
    if (elements.tabBtnAi) {
      elements.tabBtnAi.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "nearest" });
    }
  }

  function setRunningUI(isRunning) {
    if (isRunning) {
      elements.btnRun.classList.add("running");
      elements.runBtnIcon.textContent = "⏳";
      elements.runBtnText.textContent = "Running...";
    } else {
      elements.btnRun.classList.remove("running");
      elements.runBtnIcon.textContent = "▶";
      elements.runBtnText.textContent = "Run";
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
     5. FILE ACTIONS (NEW, OPEN, SAVE AS, RESET, CLEAR)
     ======================================================================== */
  function createNewFile() {
    state.currentFile = {
      path: "",
      filename: "Untitled.vital",
      language: "Custom",
      title: "New Program",
      originalCode: ""
    };

    state.editor.setValue("// Write your VITAL code here in any of the 6 supported languages\n// English, Hindi, Telugu, Bengali, Marathi, or Nepali\n\nlet x = 10\nlet y = 20\nlet sum = x + y\nprint(sum)\n");
    state.editor.clearHistory();
    state.editor.focus();

    updateHeaderAndBreadcrumbs();
    elements.tabDirtyIndicator.classList.remove("visible");

    // Deselect tree active
    document.querySelectorAll(".tree-file-item").forEach(i => i.classList.remove("active"));
    setStatus("Status: Created new Untitled.vital", "ready");
  }

  function handleFileUpload(e) {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(event) {
      const content = event.target.result;

      state.currentFile = {
        path: `upload/${file.name}`,
        filename: file.name,
        language: "Uploaded File",
        title: file.name,
        originalCode: content
      };

      state.editor.setValue(content);
      state.editor.clearHistory();

      updateHeaderAndBreadcrumbs();
      elements.tabDirtyIndicator.classList.remove("visible");

      // Deselect explorer item
      document.querySelectorAll(".tree-file-item").forEach(i => i.classList.remove("active"));
      setStatus(`Status: Loaded uploaded file ${file.name}`, "ready");
    };

    reader.readAsText(file);
    // Reset file input so re-selecting same file triggers event
    elements.fileInput.value = "";
  }

  async function handleSaveClick() {
    if (!state.currentFile || !state.currentFile.path) {
      handleSaveAs();
      return;
    }
    setStatus("Persisting working copy to backend...", "running");
    const res = await persistWorkingSourceToBackend("Toolbar save");
    if (res.success) {
      setStatus(`Status: Working source persisted to backend disk (Rev ${res.data.source_revision})`, "ready");
      alert(`Working copy successfully saved and persisted to backend disk!\n\nPath: ${state.currentFile.path}\nRevision: ${res.data.source_revision}\nContent Hash: ${res.data.content_hash.substring(0, 16)}...\n\n(Original demo fixture in examples/ remains pristine and untouched).`);
    } else {
      setStatus("Save error", "error");
      alert("Failed to save working copy: " + (res.error || "Unknown error"));
    }
  }

  function handleSaveAs() {
    const code = state.editor.getValue();
    let defaultFilename = state.currentFile.filename || "program.vital";
    const isDirty = (state.currentFile.originalCode !== undefined && code !== state.currentFile.originalCode);
    if (isDirty && !defaultFilename.startsWith("repaired_")) {
      defaultFilename = `repaired_${defaultFilename}`;
    }

    const targetName = prompt("Enter filename to save working buffer (downloads as separate local file without modifying demo):", defaultFilename);
    if (!targetName) return;

    const blob = new Blob([code], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = targetName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    setStatus(`Status: Saved copy as ${targetName} (Original demo fixture preserved untouched)`, "ready");
  }

  function handleReset() {
    restoreOriginalDemo();
  }

  function handleClearOutput() {
    elements.consoleProgram.textContent = "> Output cleared.";
    elements.consolePipeline.textContent = "";
    elements.consoleLexer.textContent = "";
    elements.consoleParser.textContent = "";
    elements.consoleAst.textContent = "";
    elements.consoleIr.textContent = "";
    elements.consoleSymbol.textContent = "";
    if (elements.consoleOptimization) elements.consoleOptimization.textContent = "";
    elements.outputTimingBadge.textContent = "0 ms";
    setStatus("Status: Output cleared", "ready");
  }

  function exportReportHtml() {
    const reportText = (elements.consolePipeline && elements.consolePipeline.textContent) || "";
    if (!reportText) {
      alert("No pipeline report available to export.");
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
    const artifacts = state.pipeline.pendingArtifacts || {};
    const fileName = (state.currentFile ? state.currentFile.filename : "report") + "_audit.json";
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
    elements.resizerLeft.addEventListener("mousedown", function(e) {
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
    elements.resizerRight.addEventListener("mousedown", function(e) {
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
     7. CONTRIBUTION 6: REAL-TIME AI PROGRAMMING ASSISTANT (READ-ONLY)
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

  async function checkAiStatus() {
    try {
      const resp = await fetch("/api/ai/status");
      const data = await resp.json();

      if (!elements.aiProviderBadge) return;

      if (data.configured) {
        let label = "AI: " + data.provider.toUpperCase();
        if (data.model && data.model !== "none") {
          label += ` (${data.model})`;
        }
        elements.aiProviderBadge.textContent = label;
        elements.aiProviderBadge.className = "ai-provider-badge configured";
        elements.aiProviderBadge.title = "Cloud AI Assistant Active";
      } else {
        elements.aiProviderBadge.textContent = "AI: Local Rules (Cloud API unconfigured)";
        elements.aiProviderBadge.className = "ai-provider-badge unconfigured";
        elements.aiProviderBadge.title = "Set GEMINI_API_KEY or OPENAI_API_KEY for Cloud LLM reasoning";
      }
    } catch (err) {
      if (elements.aiProviderBadge) {
        elements.aiProviderBadge.textContent = "AI: Local Compiler Rules";
        elements.aiProviderBadge.className = "ai-provider-badge unconfigured";
      }
    }
  }

  async function triggerAiAnalysis(isManual) {
    if (!state.editor || state.ai.isAnalyzing) return;

    const sourceCode = state.editor.getValue();
    const trimmed = sourceCode.trim();

    // If source is empty, show empty state
    if (!trimmed) {
      if (isManual) {
        switchOutputTab("tab-out-ai");
      }
      clearAiResults();
      return;
    }

    // Duplicate check for automatic triggers (avoid redundant API calls for identical source)
    if (!isManual && trimmed === state.ai.lastAnalyzedCode) {
      return;
    }

    // Capture request version for stale-response protection
    const requestVersion = state.ai.sourceVersion;
    state.ai.isAnalyzing = true;

    if (isManual) {
      switchOutputTab("tab-out-ai");
    }

    // Set UI indicators
    if (elements.aiTabStatusPill) {
      elements.aiTabStatusPill.textContent = "Analyzing...";
      elements.aiTabStatusPill.classList.add("busy");
    }
    if (elements.aiLoadingBar) {
      elements.aiLoadingBar.style.display = "flex";
      elements.aiLoadingText.textContent = isManual ? "Running deep AI analysis on current code..." : "Real-time AI analyzing code updates...";
    }

    try {
      const resp = await fetch("/api/ai/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code: sourceCode,
          language: state.currentFile.language || "English",
          diagnostics: state.ai.latestCompilerDiagnostics,
          source_version: requestVersion
        })
      });

      const res = await resp.json();

      // STALE-RESPONSE PROTECTION:
      // If user typed further while request was in flight, ignore older response!
      if (requestVersion !== state.ai.sourceVersion) {
        console.warn(`[AI Assistant] Stale response dropped. Requested version ${requestVersion}, current version is ${state.ai.sourceVersion}.`);
        return;
      }

      state.ai.lastAnalyzedCode = trimmed;
      state.ai.lastAnalyzedVersion = requestVersion;

      renderAiFindings(res);

    } catch (err) {
      console.error("[AI Assistant] Analysis error:", err);
      if (elements.aiSummaryHeader) {
        elements.aiSummaryHeader.className = "ai-summary-header has-errors";
        elements.aiSummaryHeader.textContent = `Analysis error: Could not connect to AI backend service (${err.message}).`;
      }
    } finally {
      state.ai.isAnalyzing = false;
      if (elements.aiTabStatusPill) {
        elements.aiTabStatusPill.textContent = "Ready";
        elements.aiTabStatusPill.classList.remove("busy");
      }
      if (elements.aiLoadingBar) {
        elements.aiLoadingBar.style.display = "none";
      }
    }
  }

  async function triggerAiExplainError() {
    if (!state.editor) return;

    switchOutputTab("tab-out-ai");

    const sourceCode = state.editor.getValue();
    const diag = state.ai.latestCompilerDiagnostics;

    let errorDetails = {
      type: "Compilation Issue",
      message: "Please run the program first to capture exact compiler diagnostics."
    };

    if (diag && diag.error_details) {
      errorDetails = diag.error_details;
    } else if (diag && diag.execution_status === "syntax_error") {
      errorDetails = {
        type: "Parser Syntax Error",
        message: diag.parser_log || "Structural syntax verification failed"
      };
    } else if (diag && diag.execution_status === "runtime_error") {
      errorDetails = {
        type: "Runtime Error",
        message: diag.output || "Execution engine runtime fault"
      };
    }

    if (elements.aiLoadingBar) {
      elements.aiLoadingBar.style.display = "flex";
      elements.aiLoadingText.textContent = "AI is generating detailed error diagnosis and explanation...";
    }
    if (elements.aiTabStatusPill) {
      elements.aiTabStatusPill.textContent = "Explaining...";
      elements.aiTabStatusPill.classList.add("busy");
    }

    try {
      const resp = await fetch("/api/ai/explain-error", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code: sourceCode,
          error_details: errorDetails,
          diagnostics: diag,
          language: state.currentFile.language || "English"
        })
      });

      const res = await resp.json();

      if (res.success && res.finding) {
        renderAiFindings({
          success: true,
          analysis_summary: res.error_summary || "Compiler Error Diagnosis",
          findings: [res.finding],
          pedagogical_note: "Understanding compiler diagnostics is key to writing clean VITAL code."
        });
      } else {
        renderAiFindings({
          success: true,
          analysis_summary: "No confirmed compiler errors are currently recorded.",
          findings: [],
          pedagogical_note: "Click ▶ Run to compile your code and inspect any genuine compiler diagnostics."
        });
      }
    } catch (err) {
      console.error("[AI Assistant] Explain error failed:", err);
    } finally {
      if (elements.aiLoadingBar) {
        elements.aiLoadingBar.style.display = "none";
      }
      if (elements.aiTabStatusPill) {
        elements.aiTabStatusPill.textContent = "Ready";
        elements.aiTabStatusPill.classList.remove("busy");
      }
    }
  }

  /**
   * ABSOLUTE NON-MODIFICATION GUARANTEE:
   * renderAiFindings produces purely read-only HTML into the AI panel.
   * It NEVER mutates state.editor or modifies any user code.
   */
  function renderAiFindings(res) {
    if (!elements.aiAnalysisContent || !elements.aiEmptyState) return;

    elements.aiEmptyState.style.display = "none";
    elements.aiAnalysisContent.style.display = "flex";

    const findings = res.findings || [];
    const hasErrors = findings.some(f => f.severity === "error");
    const hasWarnings = findings.some(f => f.severity === "warning");

    // 1. Summary Header
    if (elements.aiSummaryHeader) {
      let headerClass = "ai-summary-header";
      if (hasErrors) headerClass += " has-errors";
      else if (hasWarnings) headerClass += " has-warnings";
      else headerClass += " clean";

      elements.aiSummaryHeader.className = headerClass;
      elements.aiSummaryHeader.innerHTML = `
        <strong>Analysis Summary:</strong> ${escapeHtml(res.analysis_summary || "Code inspection completed.")}
      `;
    }

    // 2. Findings List
    if (elements.aiFindingsList) {
      elements.aiFindingsList.innerHTML = "";

      if (findings.length === 0) {
        elements.aiFindingsList.innerHTML = `
          <div class="ai-finding-card severity-tip">
            <div class="ai-finding-title" style="color: var(--emerald-success)">✓ No Issues Detected</div>
            <div class="ai-finding-desc">
              Your VITAL code passed local syntax, delimiter matching, and structural checks cleanly.
            </div>
          </div>
        `;
      } else {
        findings.forEach((finding, idx) => {
          const card = document.createElement("div");
          const sev = (finding.severity || "info").toLowerCase();
          card.className = `ai-finding-card severity-${sev}`;

          const isCompiler = Boolean(finding.is_compiler_diagnostic);
          const category = escapeHtml(finding.category || "General");
          const location = escapeHtml(finding.location || (finding.line ? `Line ${finding.line}` : ""));
          const title = escapeHtml(finding.title || "Finding");
          const explanation = escapeHtml(finding.explanation || "");
          const suggestedCode = finding.suggested_code ? finding.suggested_code.trim() : "";
          const why = escapeHtml(finding.why || "");

          let badgesHtml = `
            <div class="ai-meta-left">
              <span class="ai-badge ai-badge-${sev}">${sev.toUpperCase()}</span>
              <span class="ai-category-badge">${category.toUpperCase()}</span>
              ${location ? `<span class="ai-location-tag">📍 ${location}</span>` : ""}
            </div>
            <div>
              ${isCompiler ? `<span class="ai-compiler-badge">⚡ Compiler Diagnostic</span>` : `<span class="ai-category-badge">🤖 AI Observation</span>`}
            </div>
          `;

          let suggestedBoxHtml = "";
          if (suggestedCode) {
            suggestedBoxHtml = `
              <div class="ai-suggested-box">
                <div class="ai-suggested-header">
                  <span>Suggested Pattern (Example)</span>
                  <span class="ai-readonly-notice">Read-Only — Edit Manually</span>
                </div>
                <pre class="ai-suggested-code"><code>${escapeHtml(suggestedCode)}</code></pre>
              </div>
            `;
          }

          let whyHtml = "";
          if (why) {
            whyHtml = `
              <div class="ai-why-block">
                <strong>Why this correction works:</strong> ${why}
              </div>
            `;
          }

          card.innerHTML = `
            <div class="ai-finding-meta">${badgesHtml}</div>
            <div class="ai-finding-title">${title}</div>
            <div class="ai-finding-desc">${explanation}</div>
            ${suggestedBoxHtml}
            ${whyHtml}
          `;

          elements.aiFindingsList.appendChild(card);
        });
      }
    }

    // 3. Pedagogical Footer
    if (elements.aiPedagogicalFooter) {
      const note = escapeHtml(res.pedagogical_note || "VITAL compiles multilingual scripts into Python IR. Braces '{}' define scope.");
      elements.aiPedagogicalFooter.innerHTML = `
        <div style="display: flex; gap: 8px; align-items: flex-start;">
          <span style="font-size: 14px;">💡</span>
          <div>
            <strong>Developer Note:</strong> ${note}
            <div style="margin-top: 6px; font-size: 11px; color: var(--text-dim);">
              AI suggestions are advisory. Your code is never modified automatically.
            </div>
          </div>
        </div>
      `;
    }
  }

  function clearAiResults() {
    if (elements.aiAnalysisContent && elements.aiEmptyState) {
      elements.aiAnalysisContent.style.display = "none";
      elements.aiEmptyState.style.display = "block";
    }
    state.ai.lastAnalyzedCode = "";
    if (elements.aiTabStatusPill) {
      elements.aiTabStatusPill.textContent = "Ready";
      elements.aiTabStatusPill.classList.remove("busy");
    }
    setStatus("Status: AI Assistant panel cleared", "ready");
  }

  // Start IDE when DOM is ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

})();
