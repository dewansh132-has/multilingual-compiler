# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import scrolledtext, font, filedialog
import os
import sys

# Import your backend engine
from main import Compiler, RULES_FILE

def load_file():
    filepath = filedialog.askopenfilename(
        title="Open Vital Source File",
        filetypes=[("Vital Source Files", "*.vital"), ("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if filepath:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                code = f.read()
                editor.delete("1.0", tk.END)
                editor.insert(tk.END, code)
                filename = os.path.basename(filepath)
                status_var.set(f"Status: Loaded {filename}")
        except Exception as e:
            status_var.set("Status: Error Loading File")
            console.config(state=tk.NORMAL)
            console.insert(tk.END, f"\nError loading file: {e}\n", "error")
            console.config(state=tk.DISABLED)

def run_compiler():
    source_code = editor.get("1.0", tk.END).strip()
    
    if not source_code:
        console.config(state=tk.NORMAL)
        console.delete("1.0", tk.END)
        console.insert(tk.END, "> Error: No source code provided.\n", "error")
        console.config(state=tk.DISABLED)
        status_var.set("Status: Error - Empty Source Code")
        return

    # Update Status Bar
    status_var.set("Status: Compiling Pipeline...")
    root.update()

    console.config(state=tk.NORMAL)
    console.delete("1.0", tk.END)
    console.insert(tk.END, "Initiating Architecture ...\n", "info")
    
    try:
        app = Compiler(RULES_FILE)
        app.load_rules()
        
        # 1. Run the initial stages
        app.run_lexer(source_code)
        is_valid = app.run_parser(source_code)
        
        status_text = ""
        
        # 2. Only transpile and execute if the structure is valid
        if is_valid:
            py_code = app.transpile(source_code)
            app.execute(py_code)
            status_text = "Compilation Successful | IR Generated | Execution Complete"
        else:
            console.insert(tk.END, "\n[CRITICAL] Compilation stopped due to structural errors.\n", "error")
            status_text = "Parser Error Detected"

        # 3. ALWAYS fetch and display all available logs, pass or fail!
        current_src_dir = os.path.dirname(os.path.abspath(__file__))
        # PATH FIX: Go up one level to root, then into tests
        output_dir = os.path.join(os.path.dirname(current_src_dir), 'tests') 
        
        # --- UI UPDATE: Moved Execution Output to the very top! ---
        pipeline_files = [
            ("★ PROGRAM EXECUTION OUTPUT ★", "output.txt"),
            ("1. LEXICAL ANALYSIS", "lexer_log.txt"),
            ("2. PARSER VALIDATION", "parser_log.txt"),
            ("3. ABSTRACT SYNTAX TREE", "ast_log.txt"),
            ("4. TRANSPILED IR (PYTHON)", "ir.txt"),
            ("5. SEMANTIC SYMBOL TABLE", "symbol_table.txt")
        ]
        
        for title, filename in pipeline_files:
            filepath = os.path.join(output_dir, filename)
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    # If parser failed, highlight the parser log in red
                    text_color = "error" if (not is_valid and filename == "parser_log.txt") else "default"
                    header_color = "error" if (not is_valid and filename == "parser_log.txt") else "header"
                    
                    console.insert(tk.END, f"\n{'━'*50}\n", "separator")
                    console.insert(tk.END, f"  {title}  \n", header_color)
                    console.insert(tk.END, f"{'━'*50}\n", "separator")
                    console.insert(tk.END, f.read() + "\n", text_color)
        
        status_var.set(f"Status: {status_text}")
            
    except Exception as e:
        console.insert(tk.END, f"\nGUI Error: {e}\n", "error")
        status_var.set("Status: Fatal System Error")
        
    console.config(state=tk.DISABLED)

# --- HOVER EFFECTS FOR BUTTONS (Oceanic Slate Theme) ---
def on_enter_run(e): run_btn['background'] = '#2563EB' # Lighter Blue hover
def on_leave_run(e): run_btn['background'] = '#1D4ED8' # Deep Blue normal
def on_enter_load(e): load_btn['background'] = '#475569' # Lighter Slate hover
def on_leave_load(e): load_btn['background'] = '#334155' # Deep Slate normal

# --- GUI SETUP ---
root = tk.Tk()
root.title("Multilingual Programming Language Compiler")
root.geometry("1150x700")
root.configure(bg="#0F172A") # Very Deep Navy Blue/Slate

# --- FONTS ---
editor_font = font.Font(family="Consolas", size=13) # Switched to Consolas for coding feel
console_font = font.Font(family="Consolas", size=11)

# Status Bar Variable
status_var = tk.StringVar()
status_var.set("Status: System Ready | Multilingual Engine Loaded")

# PanedWindow (Draggable split)
main_pane = tk.PanedWindow(root, orient=tk.HORIZONTAL, bg="#1E293B", sashwidth=6, sashrelief=tk.FLAT, bd=0)
main_pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

left_frame = tk.Frame(main_pane, bg="#0F172A")
right_frame = tk.Frame(main_pane, bg="#0F172A")

main_pane.add(left_frame, minsize=400) 
main_pane.add(right_frame, minsize=500)

# Editor (Left Side) - Beautiful slate background with silver text and cyan cursor
tk.Label(left_frame, text="Source Code (.vital)", fg="#38BDF8", bg="#0F172A", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0,5))
editor = scrolledtext.ScrolledText(left_frame, bg="#1E293B", fg="#E2E8F0", insertbackground="#22D3EE", font=editor_font, relief=tk.FLAT, highlightthickness=1, highlightbackground="#334155", padx=10, pady=10)
editor.pack(fill=tk.BOTH, expand=True, pady=(0,10))

# Buttons Framework
btn_frame = tk.Frame(left_frame, bg="#0F172A")
btn_frame.pack(fill=tk.X)

# Load File Button (Slate Gray)
load_btn = tk.Button(btn_frame, text="📂 LOAD .VITAL FILE", bg="#334155", fg="#F8FAFC", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, bd=0, cursor="hand2", pady=8, command=load_file)
load_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
load_btn.bind("<Enter>", on_enter_load)
load_btn.bind("<Leave>", on_leave_load)

# Run Pipeline Button (Ocean Blue)
run_btn = tk.Button(btn_frame, text="▶ COMPILE & RUN ", bg="#1D4ED8", fg="white", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, bd=0, cursor="hand2", pady=8, command=run_compiler)
run_btn.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(5, 0))
run_btn.bind("<Enter>", on_enter_run)
run_btn.bind("<Leave>", on_leave_run)

# Console (Right Side) - Ultra-dark navy for high contrast logs
tk.Label(right_frame, text="Architecture Pipeline Logs", fg="#38BDF8", bg="#0F172A", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0,5))
console = scrolledtext.ScrolledText(right_frame, bg="#020617", fg="#94A3B8", font=console_font, relief=tk.FLAT, highlightthickness=1, highlightbackground="#334155", padx=10, pady=10, tabs=(180, 280))
console.pack(fill=tk.BOTH, expand=True)

# Console Text Tag Styling (Vibrant Modern Colors)
console.tag_config("header", foreground="#FBBF24", font=("Consolas", 12, "bold")) # Warm Amber for section titles
console.tag_config("separator", foreground="#334155") # Subtle slate dividers
console.tag_config("error", foreground="#F43F5E", font=("Consolas", 11, "bold")) # Vibrant Rose Red for errors
console.tag_config("info", foreground="#38BDF8", font=("Consolas", 11, "bold")) # Sky Blue for system info
console.tag_config("default", foreground="#A78BFA", font=("Consolas", 11)) # Soft Purple/Slate for general execution text

console.config(state=tk.DISABLED)

# Status Bar (Bottom)
status_bar = tk.Label(root, textvariable=status_var, bg="#1D4ED8", fg="white", font=("Segoe UI", 9, "bold"), anchor="w", padx=10, pady=4)
status_bar.pack(side=tk.BOTTOM, fill=tk.X)

root.mainloop()