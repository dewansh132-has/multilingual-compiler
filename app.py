# -*- coding: utf-8 -*-
"""
app.py — Main Entry Point for the VITAL Multilingual Web IDE

Usage:
    python app.py

Then open your browser to:
    http://localhost:8000
"""

import os
import sys
import webbrowser

# Ensure UTF-8 console output on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from web.server import app

def main():
    port = int(os.environ.get('PORT', 8000))
    host = os.environ.get('HOST', '127.0.0.1')
    
    print("=" * 65)
    print("  🌐 VITAL MULTILINGUAL PROGRAMMING LANGUAGE COMPILER — WEB IDE")
    print("=" * 65)
    print(f"  • IDE Interface:     http://{host}:{port}")
    print(f"  • API Endpoint:      http://{host}:{port}/api/run")
    print(f"  • Supported Scripts: English, Hindi, Telugu, Bengali, Marathi, Nepali")
    print(f"  • Compiler Engine:   Existing VITAL Pipeline (src/main.py)")
    print(f"  • Desktop GUI:       src/gui.py remains available")
    print("=" * 65)
    print("  Press Ctrl+C to stop the server.\n")

    # Start Flask dev server
    app.run(host=host, port=port, debug=False, threaded=True)

if __name__ == '__main__':
    main()
